-module(wiggle_app).

-behaviour(application).

-include("wiggle.hrl").
-include("wiggle_version.hrl").

%% Application callbacks
-export([start/2, stop/1]).

-export([dispatchs/0]).
-ignore_xref([dispatchs/0]).
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

dispatchs() ->
    API = application:get_env(wiggle, api, all),
    %% OAuth related rules
    [
     {<<"/api/:version/oauth/token">>,
      cowboy_oauth_token, []},
     {<<"/api/:version/oauth/auth">>,
      cowboy_oauth_auth, [<<"/api/", ?V2/binary, "/oauth/2fa">>]},
     {<<"/api/:version/oauth/2fa">>,
      cowboy_oauth_2fa, []},
     {<<"/api/:version/sessions/[...]">>,
      wiggle_rest_h, [wiggle_session_h]}] ++
        %% Snarl related rules (we only exclude them if oauth is selected)
        case API of
            oauth2 ->
                [];
            _ ->
                [{<<"/api/:version/users/[...]">>,
                  wiggle_rest_h, [wiggle_user_h]},
                 {<<"/api/:version/roles/[...]">>,
                  wiggle_rest_h, [wiggle_role_h]},
                 {<<"/api/:version/clients/[...]">>,
                  wiggle_rest_h, [wiggle_client_h]},
                 {<<"/api/:version/orgs/[...]">>,
                  wiggle_rest_h, [wiggle_org_h]}]
        end ++
        %% Sniffle realted rules (we only use them if all is selected)
        case API of
            all ->
                [{<<"/api/:version/cloud/[...]">>,
                  wiggle_rest_h, [wiggle_cloud_h]},
                 {<<"/api/:version/hypervisors/[...]">>,
                  wiggle_rest_h, [wiggle_hypervisor_h]},
                 {<<"/api/:version/dtrace/:uuid/stream">>,
                  wiggle_dtrace_stream, []},
                 {<<"/api/:version/dtrace/[...]">>,
                  wiggle_rest_h, [wiggle_dtrace_h]},
                 {<<"/api/:version/vms/:uuid/console">>,
                  wiggle_console_h, []},
                 {<<"/api/:version/vms/:uuid/vnc">>,
                  wiggle_vnc_h, []},
                 {<<"/api/:version/vms/[...]">>,
                  wiggle_rest_h, [wiggle_vm_h]},
                 {<<"/api/:version/ipranges/[...]">>,
                  wiggle_rest_h, [wiggle_iprange_h]},
                 {<<"/api/:version/networks/[...]">>,
                  wiggle_rest_h, [wiggle_network_h]},
                 {<<"/api/:version/groupings/[...]">>,
                  wiggle_rest_h, [wiggle_grouping_h]},
                 {<<"/api/:version/datasets/[...]">>,
                  wiggle_rest_h, [wiggle_dataset_h]},
                 {<<"/api/:version/packages/[...]">>,
                  wiggle_rest_h, [wiggle_package_h]}];
            _ ->
                []
        end ++
        case application:get_env(wiggle, ui_path) of
            {ok, UIDir} ->
                [{"/", cowboy_static, {file, filename:join(UIDir, "index.html")}},
                 {"/[...]", cowboy_static, {dir, UIDir}}];
            _ ->
                []
        end.
