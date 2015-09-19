-module(wiggle_app).

-behaviour(application).

-include("wiggle.hrl").
-include("wiggle_version.hrl").

%% Application callbacks
-export([start/2, stop/1]).

-export([dispatches/0]).
-ignore_xref([dispatches/0]).
%% ===================================================================
%% Application callbacks
%% ===================================================================

start(_StartType, _StartArgs) ->
    load_schemas(),
    case application:get_env(wiggle, http_server, true) of
        true ->
            application:start(folsom),
            {ok, Port} = application:get_env(wiggle, port),
            {ok, Compression} = application:get_env(wiggle, compression),
            {ok, Acceptors} = application:get_env(wiggle, acceptors),
            DPRules = dispatches(),
            Dispatch = cowboy_router:compile([{'_', DPRules}]),

            {ok, _} = cowboy:start_http(http, Acceptors, [{port, Port}],
                                        [{compress, Compression},
                                         {env, [{dispatch, Dispatch}]}]),
            case application:get_env(wiggle, ssl) of
                {ok, on} ->
                    {ok, SSLPort} = application:get_env(wiggle, ssl_port),
                    {ok, SSLCA} = application:get_env(wiggle, ssl_cacertfile),
                    {ok, SSLCert} = application:get_env(wiggle, ssl_certfile),
                    {ok, SSLKey} = application:get_env(wiggle, ssl_keyfile),
                    {ok, _} = cowboy:start_https(https, Acceptors,
                                                 [{port, SSLPort},
                                                  {cacertfile, SSLCA},
                                                  {certfile, SSLCert},
                                                  {keyfile, SSLKey}],
                                                 [{compress, Compression},
                                                  {env, [{dispatch, Dispatch}]}]);
                {ok, spdy} ->
                    {ok, SSLPort} = application:get_env(wiggle, ssl_port),
                    {ok, SSLCA} = application:get_env(wiggle, ssl_cacertfile),
                    {ok, SSLCert} = application:get_env(wiggle, ssl_certfile),
                    {ok, SSLKey} = application:get_env(wiggle, ssl_keyfile),
                    {ok, _} = cowboy:start_spdy(spdy, Acceptors,
                                                [{port, SSLPort},
                                                 {cacertfile, SSLCA},
                                                 {certfile, SSLCert},
                                                 {keyfile, SSLKey}],
                                                [{compress, Compression},
                                                 {env, [{dispatch, Dispatch}]}]);
                _ ->
                    ok
            end,
            R = wiggle_sup:start_link(),
            lager_watchdog_srv:set_version(?VERSION),
            wiggle_snmp_h:start(),
            R;
        _ ->
            wiggle_sup:start_link()
    end.

stop(_State) ->
    ok.

load_schemas() ->
    FileRegexp = ".*\.json$",
    Schemas = filelib:fold_files(
                code:priv_dir(wiggle), FileRegexp, true,
                fun(File, Acc) ->
                        io:format("Loading file: ~s~n", [File]),
                        BaseName = filename:basename(File),
                        Key = list_to_atom(filename:rootname(BaseName)),
                        {ok, Bin} = file:read_file(File),
                        JSX = jsx:decode(Bin),
                        ok = jesse:add_schema(Key, JSX),
                        [Key | Acc]
                end, []),
    lager:info("[schemas] Loaded schemas: ~p", [Schemas]).

dispatches() ->
    API = application:get_env(wiggle, api, all),
    UIDir = case application:get_env(wiggle, ui_path) of
                {ok, D} ->
                    D;
                _ ->
                    undefined
            end,
    wiggle:dispatches(API, UIDir).
