%%% -*- erlang -*-
%%%
%%% Tests for server certificate validation (quic_cert) and the
%%% client-side server-authentication path in quic_connection.
%%%
%%% Regression coverage for GHSA-2r8v-p65x-3663: a QUIC client must
%%% reject a server it cannot authenticate when `verify' is enabled.

-module(quic_cert_tests).

-include_lib("eunit/include/eunit.hrl").

-define(CONNECT_TIMEOUT, 3000).

%%====================================================================
%% quic_cert:validate_server/4 unit tests
%%====================================================================

validate_server_test_() ->
    case gen_cert("/CN=localhost", "subjectAltName=DNS:localhost,IP:127.0.0.1") of
        {ok, Leaf, _Key} ->
            {ok, Other, _} = gen_cert("/CN=other", "subjectAltName=DNS:other"),
            [
                {"trusted self-signed leaf with matching name",
                    ?_assertEqual(ok, quic_cert:validate_server(Leaf, [], [Leaf], <<"localhost">>))},
                {"no trust anchors is rejected",
                    ?_assertEqual(
                        {error, no_trust_anchors},
                        quic_cert:validate_server(Leaf, [], [], <<"localhost">>)
                    )},
                {"untrusted anchor is rejected",
                    ?_assertEqual(
                        {error, unknown_ca},
                        quic_cert:validate_server(Leaf, [], [Other], <<"localhost">>)
                    )},
                {"hostname mismatch is rejected",
                    ?_assertMatch(
                        {error, {hostname_mismatch, _}},
                        quic_cert:validate_server(Leaf, [], [Leaf], <<"evil.example">>)
                    )},
                {"missing certificate is rejected",
                    ?_assertEqual(
                        {error, no_certificate},
                        quic_cert:validate_server(undefined, [], [Leaf], <<"localhost">>)
                    )},
                {"undefined server name skips the hostname check",
                    ?_assertEqual(ok, quic_cert:validate_server(Leaf, [], [Leaf], undefined))}
            ];
        {error, _} ->
            []
    end.

%%====================================================================
%% End-to-end client behaviour
%%====================================================================

client_verification_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun(Ctx) ->
        case Ctx of
            skip ->
                [];
            #{port := Port, cert := Cert} ->
                [
                    {"verify=false connects to a self-signed server",
                        {timeout, 30, ?_assertEqual(connected, connect(Port, #{verify => false}))}},
                    {"verify=true with the right anchor and name connects",
                        {timeout, 30,
                            ?_assertEqual(
                                connected,
                                connect(Port, #{
                                    verify => true,
                                    cacerts => [Cert],
                                    server_name => <<"localhost">>
                                })
                            )}},
                    {"verify=true without a trust anchor is rejected",
                        {timeout, 30,
                            ?_assertNotEqual(
                                connected,
                                connect(Port, #{verify => true, server_name => <<"localhost">>})
                            )}},
                    {"verify=true with a name mismatch is rejected",
                        {timeout, 30,
                            ?_assertNotEqual(
                                connected,
                                connect(Port, #{
                                    verify => true,
                                    cacerts => [Cert],
                                    server_name => <<"wrong.example">>
                                })
                            )}}
                ]
        end
    end}.

setup() ->
    case gen_cert("/CN=localhost", "subjectAltName=DNS:localhost,IP:127.0.0.1") of
        {ok, Cert, Key} ->
            {ok, _} = application:ensure_all_started(quic),
            {ok, Server} = quic_test_echo_server:start(#{cert => Cert, key => Key}),
            (maps:merge(#{cert => Cert}, Server))#{server => Server};
        {error, _} ->
            skip
    end.

cleanup(skip) ->
    ok;
cleanup(#{server := Server}) ->
    quic_test_echo_server:stop(Server).

%% Run each connection in its own owner process so events from one
%% attempt never leak into the next attempt's mailbox. The `connected'
%% event is keyed on the connection pid while error notifications are
%% keyed on the connection ref, so match on any source.
connect(Port, Opts0) ->
    Parent = self(),
    {Pid, MRef} = spawn_monitor(fun() ->
        Opts = Opts0#{alpn => [<<"echo">>]},
        {ok, Conn} = quic:connect("127.0.0.1", Port, Opts, self()),
        Result =
            receive
                {quic, _, {connected, _Info}} -> connected;
                {quic, _, {closed, Reason}} -> {closed, Reason};
                {quic, _, {error, Reason}} -> {error, Reason}
            after ?CONNECT_TIMEOUT -> timeout
            end,
        catch quic:close(Conn),
        Parent ! {result, self(), Result}
    end),
    receive
        {result, Pid, Result} ->
            erlang:demonitor(MRef, [flush]),
            Result;
        {'DOWN', MRef, process, Pid, DownReason} ->
            {crashed, DownReason}
    after ?CONNECT_TIMEOUT + 3000 ->
        erlang:demonitor(MRef, [flush]),
        exit(Pid, kill),
        timeout
    end.

%%====================================================================
%% HTTP/3 client inherits the same verification
%%====================================================================

h3_verification_test_() ->
    {setup, fun h3_setup/0, fun h3_cleanup/1, fun(Ctx) ->
        case Ctx of
            skip ->
                [];
            #{port := Port, cert := Cert} ->
                [
                    {"h3 verify_none connects",
                        {timeout, 30,
                            ?_assertEqual(connected, h3_connect(Port, #{verify => verify_none}))}},
                    {"h3 verify_peer with the right anchor connects",
                        {timeout, 30,
                            ?_assertEqual(
                                connected,
                                h3_connect(Port, #{verify => verify_peer, cacerts => [Cert]})
                            )}},
                    {"h3 verify_peer without a trust anchor is rejected",
                        {timeout, 30,
                            ?_assertMatch(
                                {error, _}, h3_connect(Port, #{verify => verify_peer})
                            )}}
                ]
        end
    end}.

h3_setup() ->
    case gen_cert("/CN=localhost", "subjectAltName=DNS:localhost,IP:127.0.0.1") of
        {ok, Cert, Key} ->
            {ok, _} = application:ensure_all_started(quic),
            Name = list_to_atom("quic_h3_verify_" ++ suffix()),
            {ok, _} = quic_h3:start_server(Name, 0, #{cert => Cert, key => Key}),
            {ok, Port} = quic:get_server_port(Name),
            #{name => Name, port => Port, cert => Cert};
        {error, _} ->
            skip
    end.

h3_cleanup(skip) ->
    ok;
h3_cleanup(#{name := Name}) ->
    catch quic:stop_server(Name),
    ok.

%% Connect over HTTP/3 to localhost and report whether the handshake
%% completed. `server_name' is set by quic_h3 to the connect host.
h3_connect(Port, Opts0) ->
    Opts = Opts0#{sync => true, connect_timeout => ?CONNECT_TIMEOUT},
    case quic_h3:connect("localhost", Port, Opts) of
        {ok, Conn} ->
            catch quic_h3:close(Conn),
            connected;
        {error, Reason} ->
            {error, Reason}
    end.

%%====================================================================
%% Helpers
%%====================================================================

%% Generate a self-signed certificate with the given subject and
%% SAN extension. Returns the leaf DER and the decoded private key,
%% or `{error, _}' when openssl is unavailable.
gen_cert(Subject, SanExt) ->
    Dir = filename:join("/tmp", "quic_cert_test_" ++ suffix()),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    CertFile = filename:join(Dir, "cert.pem"),
    KeyFile = filename:join(Dir, "key.pem"),
    Cmd = lists:flatten(
        io_lib:format(
            "openssl req -x509 -newkey rsa:2048 -keyout ~s -out ~s "
            "-days 1 -nodes -subj '~s' -addext '~s' 2>/dev/null",
            [KeyFile, CertFile, Subject, SanExt]
        )
    ),
    _ = os:cmd(Cmd),
    case {filelib:is_file(CertFile), filelib:is_file(KeyFile)} of
        {true, true} ->
            {ok, CertPem} = file:read_file(CertFile),
            {ok, KeyPem} = file:read_file(KeyFile),
            [{'Certificate', CertDer, _}] = public_key:pem_decode(CertPem),
            {ok, CertDer, decode_key(KeyPem)};
        _ ->
            {error, cert_generation_failed}
    end.

decode_key(KeyPem) ->
    case public_key:pem_decode(KeyPem) of
        [{'RSAPrivateKey', Der, not_encrypted}] ->
            public_key:der_decode('RSAPrivateKey', Der);
        [{'ECPrivateKey', Der, not_encrypted}] ->
            public_key:der_decode('ECPrivateKey', Der);
        [{'PrivateKeyInfo', Der, not_encrypted}] ->
            public_key:der_decode('PrivateKeyInfo', Der);
        [{_Type, Der, not_encrypted}] ->
            Der
    end.

suffix() ->
    integer_to_list(erlang:unique_integer([positive, monotonic])).
