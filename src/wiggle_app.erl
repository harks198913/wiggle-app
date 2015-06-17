-module(wiggle_app).

-behaviour(application).

-include("wiggle_version.hrl").

%% Application callbacks
-export([start/2, stop/1]).

-export([dispatchs/0]).
-ignore_xref([dispatchs/0]).
%% ===================================================================
%% Application callbacks
%% ===================================================================

start(_StartType, _StartArgs) ->
    case (catch eplugin:wait_for_init()) of
        {'EXIT', Why} ->
            lager:warning("Error waiting for eplugin init: ~p", [Why]),
            lager:warning("Your plugins are probably taking too long to load, "
                          "and some wiggle:dispatchs hooks may not run.");
        ok -> ok
    end,
    load_schemas(),
    case application:get_env(wiggle, http_server, true) of
        true ->
            application:start(folsom),
            {ok, Port} = application:get_env(wiggle, port),
            {ok, Compression} = application:get_env(wiggle, compression),
            {ok, Acceptors} = application:get_env(wiggle, acceptors),
            DPRules = dispatchs(),
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
            wiggle_snmp_handler:start(),
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

dispatchs() ->
    PluginDispatchs = eplugin:fold('wiggle:dispatchs', []),
    API = application:get_env(wiggle, api, all),
    %% OAuth related rules
    [
     {<<"/api/:version/oauth/token">>,
      cowboy_oauth_token, [<<"/api/0.2.0/oauth/2fa">>]},
     {<<"/api/:version/oauth/auth">>,
      cowboy_oauth_auth, []},
     {<<"/api/:version/oauth/2fa">>,
      cowboy_oauth_2fa, []},
     {<<"/api/:version/sessions/[...]">>,
      wiggle_rest_handler, [wiggle_session_handler]}] ++
        %% Snarl related rules (we only exclude them if oauth is selected)
        case API of
            oauth2 ->
                [];
            _ ->
                [{<<"/api/:version/users/[...]">>,
                  wiggle_rest_handler, [wiggle_user_handler]},
                 {<<"/api/:version/roles/[...]">>,
                  wiggle_rest_handler, [wiggle_role_handler]},
                 {<<"/api/:version/clients/[...]">>,
                  wiggle_rest_handler, [wiggle_client_handler]},
                 {<<"/api/:version/orgs/[...]">>,
                  wiggle_rest_handler, [wiggle_org_handler]}]
        end ++
        %% Sniffle realted rules (we only use them if all is selected)
        case API of
            all ->
                [{<<"/api/:version/cloud/[...]">>,
                  wiggle_rest_handler, [wiggle_cloud_handler]},
                 {<<"/api/:version/hypervisors/[...]">>,
                  wiggle_rest_handler, [wiggle_hypervisor_handler]},
                 {<<"/api/:version/dtrace/:uuid/stream">>,
                  wiggle_dtrace_stream, []},
                 {<<"/api/:version/dtrace/[...]">>,
                  wiggle_rest_handler, [wiggle_dtrace_handler]},
                 {<<"/api/:version/vms/:uuid/console">>,
                  wiggle_console_handler, []},
                 {<<"/api/:version/vms/:uuid/vnc">>,
                  wiggle_vnc_handler, []},
                 {<<"/api/:version/vms/[...]">>,
                  wiggle_rest_handler, [wiggle_vm_handler]},
                 {<<"/api/:version/ipranges/[...]">>,
                  wiggle_rest_handler, [wiggle_iprange_handler]},
                 {<<"/api/:version/networks/[...]">>,
                  wiggle_rest_handler, [wiggle_network_handler]},
                 {<<"/api/:version/groupings/[...]">>,
                  wiggle_rest_handler, [wiggle_grouping_handler]},
                 {<<"/api/:version/datasets/[...]">>,
                  wiggle_rest_handler, [wiggle_dataset_handler]},
                 {<<"/api/:version/packages/[...]">>,
                  wiggle_rest_handler, [wiggle_package_handler]}];
            _ ->
                []
        end ++
        PluginDispatchs ++
        case application:get_env(wiggle, ui_path) of
            {ok, UIDir} ->
                [{"/", cowboy_static, {file, filename:join(UIDir, "index.html")}},
                 {"/[...]", cowboy_static, {dir, UIDir}}];
            _ ->
                []
        end.
