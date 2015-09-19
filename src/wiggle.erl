-module(wiggle).

-include("wiggle.hrl").

-export([start/0,
         dispatches/2,
         auth_dispatch/1,
         snarl_dispatch/0,
         snarl_dispatch/1,
         sniffle_dispatch/0,
         sniffle_dispatch/1]).

-ignore_xref([start/0,
              dispatches/2,
              auth_dispatch/1,
              snarl_dispatch/0,
              snarl_dispatch/1,
              sniffle_dispatch/0,
              sniffle_dispatch/1]).

-ignore_xref([start/0]).


start() ->
    application:start(sasl),
    lager:start(),
    application:start(mdns_client_lib),
    application:start(libsnarlmatch),
    application:start(libchunter),
    application:start(libsnarl),
    application:start(libsniffle),
    application:start(jsx),
    application:start(lager),
    application:start(mimetypes),
    application:start(crypto),
    application:start(ranch),
    application:start(cowboy),
    application:start(mnesia),
    application:start(snmp),
    application:start(wiggle).


auth_dispatch(V) ->
    [{<<"/api/:version/oauth/token">>,
      cowboy_oauth_token, []},
     {<<"/api/:version/oauth/auth">>,
      cowboy_oauth_auth, [<<"/api/", V/binary, "/oauth/2fa">>]},
     {<<"/api/:version/oauth/2fa">>,
      cowboy_oauth_2fa, []},
     {<<"/api/:version/sessions/[...]">>,
      wiggle_rest_h, [wiggle_session_h]}].
snarl_dispatch(true) ->
    snarl_dispatch();
snarl_dispatch(_) ->
    [].

snarl_dispatch() ->
    [{<<"/api/:version/users/[...]">>,
      wiggle_rest_h, [wiggle_user_h]},
     {<<"/api/:version/roles/[...]">>,
      wiggle_rest_h, [wiggle_role_h]},
     {<<"/api/:version/clients/[...]">>,
      wiggle_rest_h, [wiggle_client_h]},
     {<<"/api/:version/scope/[...]">>,
      wiggle_rest_h, [wiggle_scope_h]},
     {<<"/api/:version/orgs/[...]">>,
      wiggle_rest_h, [wiggle_org_h]}].

sniffle_dispatch(true) ->
    sniffle_dispatch();
sniffle_dispatch(_) ->
    [].

sniffle_dispatch() ->
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
      wiggle_rest_h, [wiggle_package_h]}].


dispatches(API, UIDir) ->
    %% OAuth related rules
    [{<<"/api/:version/oauth/token">>,
      cowboy_oauth_token, []},
     {<<"/api/:version/oauth/auth">>,
      cowboy_oauth_auth, [<<"/api/", ?V2/binary, "/oauth/2fa">>]},
     {<<"/api/:version/oauth/2fa">>,
      cowboy_oauth_2fa, []},
     {<<"/api/:version/sessions/[...]">>,
      wiggle_rest_h, [wiggle_session_h]}] ++
        %% Snarl related rules (we only exclude them if oauth is selected)
        snarl_dispatch(API =/= oauth) ++
        %% Sniffle realted rules (we only use them if all is selected)
        sniffle_dispatch(API =:= all) ++
        case UIDir of
            undefined ->
                [];
            _ ->
                [{"/", cowboy_static, {file, filename:join(UIDir, "index.html")}},
                 {"/[...]", cowboy_static, {dir, UIDir}}]
        end.
