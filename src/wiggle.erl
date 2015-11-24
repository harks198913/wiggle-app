-module(wiggle).

-include("wiggle.hrl").

-export([start/0,
         dispatches/2,
         snarl_dispatch/0,
         snarl_dispatch/1,
         sniffle_dispatch/0,
         sniffle_dispatch/1]).

-ignore_xref([start/0,
              dispatches/2,
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


snarl_dispatch(true) ->
    snarl_dispatch();
snarl_dispatch(_) ->
    [].

h(P, H) ->
    {<<"/api/:version/", P/binary>>,   wiggle_rest_h, [H]}.

hs(Hs) ->
    [h(P, H) || {P, H} <- Hs].
snarl_dispatch() ->
    hs([{<<"users/[...]">>,   wiggle_user_h},
        {<<"roles/[...]">>,   wiggle_role_h},
        {<<"clients/[...]">>, wiggle_client_h},
        {<<"scopes/[...]">>,  wiggle_scope_h},
        {<<"orgs/[...]">>,    wiggle_org_h}]).

sniffle_dispatch(true) ->
    sniffle_dispatch();

sniffle_dispatch(_) ->
    [].

sniffle_dispatch() ->
    [{<<"/api/:version/vms/:uuid/console">>, wiggle_console_h, []},
     {<<"/api/:version/vms/:uuid/vnc">>, wiggle_vnc_h, []},
     {<<"/api/:version/dtrace/:uuid/stream">>, wiggle_dtrace_stream, []}] ++
        hs([{<<"cloud/[...]">>,       wiggle_cloud_h},
            {<<"hypervisors/[...]">>, wiggle_hypervisor_h},
            {<<"dtrace/[...]">>,      wiggle_dtrace_h},
            {<<"vms/[...]">>,         wiggle_vm_h},
            {<<"ipranges/[...]">>,    wiggle_iprange_h},
            {<<"networks/[...]">>,    wiggle_network_h},
            {<<"groupings/[...]">>,   wiggle_grouping_h},
            {<<"datasets/[...]">>,    wiggle_dataset_h},
            {<<"packages/[...]">>,    wiggle_package_h}]).


dispatches(API, UIDir) ->
    %% OAuth related rules
    [{<<"/api/:version/oauth/token">>, cowboy_oauth_token, []},
     {<<"/api/:version/oauth/auth">>,
      cowboy_oauth_auth, [<<"/api/", ?V2/binary, "/oauth/2fa">>]},
     {<<"/api/:version/oauth/2fa">>,
      cowboy_oauth_2fa, []},
     h(<<"sessions/[...]">>, wiggle_session_h)] ++
        %% Snarl related rules (we only exclude them if oauth is selected)
        snarl_dispatch(API =/= oauth) ++
        %% Sniffle realted rules (we only use them if all is selected)
        sniffle_dispatch(API =:= all) ++
        case UIDir of
            undefined ->
                [];
            _ ->
                [{"/", cowboy_static,
                  {file, filename:join(UIDir, "index.html")}},
                 {"/[...]", cowboy_static, {dir, UIDir}}]
        end.
