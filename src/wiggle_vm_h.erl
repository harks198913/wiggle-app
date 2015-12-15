-module(wiggle_vm_h).

-include("wiggle.hrl").

-define(CACHE, vm).
-define(LIST_CACHE, vm_list).
-define(FULL_CACHE, vm_full_list).

-export([allowed_methods/3,
         get/1,
         permission_required/3,
         read/2,
         create/3,
         write/3,
         delete/2,
         schema/1,
         service_available/1]).

-behaviour(wiggle_rest_h).


-define(LIB(Call),
        Start = erlang:system_time(micro_seconds),
        case Call of
            ok ->
                ?MSniffle(?P(State), Start),
                {true, Req, State};
            GuardCallError ->
                ?MSniffle(?P(State), Start),
                lager:error("Error: ~p", [GuardCallError]),
                {false, Req, State}
        end).
service_available(#state{path = [?UUID(_Vm), <<"metrics">>| _]}) ->
    wiggle_h:service_available() andalso
        application:get_env(dqe, backend) =/= undefined;
service_available(_) ->
    wiggle_h:service_available().

allowed_methods(_Version, _Token, []) ->
    [<<"GET">>, <<"POST">>];

allowed_methods(_Version, _Token, [?UUID(_Vm)]) ->
    [<<"GET">>, <<"PUT">>, <<"DELETE">>];

allowed_methods(?V2, _Token, [?UUID(_Vm), <<"metrics">>| _]) ->
    [<<"GET">>];

allowed_methods(?V2, _Token, [?UUID(_Vm), <<"config">>]) ->
    [<<"PUT">>];

allowed_methods(?V2, _Token, [?UUID(_Vm), <<"package">>]) ->
    [<<"PUT">>];

allowed_methods(?V2, _Token, [?UUID(_Vm), <<"state">>]) ->
    [<<"PUT">>];

allowed_methods(_Version, _Token, [<<"dry_run">>]) ->
    [<<"PUT">>];

allowed_methods(_Version, _Token, [?UUID(_Vm), <<"hypervisor">>]) ->
    [<<"DELETE">>];

allowed_methods(_Version, _Token, [?UUID(_Vm), <<"owner">>]) ->
    [<<"PUT">>];

allowed_methods(_Version, _Token, [?UUID(_Vm), <<"services">>]) ->
    [<<"PUT">>];

allowed_methods(_Version, _Token, [?UUID(_Vm), <<"metadata">>|_]) ->
    [<<"PUT">>, <<"DELETE">>];

allowed_methods(_Version, _Token, [?UUID(_Vm), <<"nics">>, _Mac]) ->
    [<<"PUT">>, <<"DELETE">>];

allowed_methods(_Version, _Token, [?UUID(_Vm), <<"nics">>]) ->
    [<<"POST">>];

allowed_methods(_Version, _Token, [?UUID(_Vm), <<"snapshots">>, _ID]) ->
    [<<"PUT">>, <<"DELETE">>];

allowed_methods(_Version, _Token, [?UUID(_Vm), <<"snapshots">>]) ->
    [<<"POST">>];

allowed_methods(_Version, _Token, [?UUID(_Vm), <<"fw_rules">>, _ID]) ->
    [<<"DELETE">>]; %% We might need to add PUT later.

allowed_methods(_Version, _Token, [?UUID(_Vm), <<"fw_rules">>]) ->
    [<<"POST">>];

allowed_methods(_Version, _Token, [?UUID(_Vm), <<"backups">>, _ID]) ->
    [<<"PUT">>, <<"DELETE">>];

allowed_methods(_Version, _Token, [?UUID(_Vm), <<"backups">>]) ->
    [<<"GET">>, <<"POST">>].

get(State = #state{path = [?UUID(Vm), <<"backups">>, Snap]}) ->
    case wiggle_vm_h:get(State#state{path=[?UUID(Vm)]}) of
        {ok, Obj} ->
            case jsxd:get([Snap], ft_vm:backups(Obj)) of
                undefined -> not_found;
                {ok, _} -> {ok, Obj}
            end;
        E ->
            E
    end;

get(State = #state{path = [?UUID(Vm), <<"snapshots">>, Snap]}) ->
    case wiggle_vm_h:get(State#state{path=[?UUID(Vm)]}) of
        {ok, Obj} ->
            case jsxd:get([Snap], ft_vm:snapshots(Obj)) of
                undefined -> not_found;
                {ok, _} -> {ok, Obj}
            end;
        E ->
            E
    end;

get(State = #state{path = [?UUID(Vm), <<"nics">>, Mac]}) ->
    case wiggle_vm_h:get(State#state{path=[?UUID(Vm)]}) of
        {ok, Obj} ->
            Macs = [jsxd:get([<<"mac">>], <<>>, N) ||
                       N <- jsxd:get([<<"networks">>], [], ft_vm:config(Obj))],
            case lists:member(Mac, Macs) of
                true ->
                    {ok, Obj};
                _ ->
                    not_found
            end;
        E ->
            E
    end;

get(State = #state{path = [?UUID(Vm), <<"fw_rules">>, IDB]}) ->
    case wiggle_vm_h:get(State#state{path=[?UUID(Vm)]}) of
        {ok, Obj} ->
            ID = binary_to_integer(IDB),
            case find_rule(ID, Obj) of
                {ok, _} ->
                    {ok, Obj};
                _ ->
                    not_found
            end;
        E ->
            E
    end;

get(#state{path = [?UUID(_Vm), <<"metrics">>]}) ->
    {ok, erlang:system_time(micro_seconds)};

get(State = #state{path = [?UUID(Vm) | _]}) ->
    Start = erlang:system_time(micro_seconds),
    R = case application:get_env(wiggle, vm_ttl) of
            {ok, {TTL1, TTL2}} ->
                wiggle_h:timeout_cache_with_invalid(
                  ?CACHE, Vm, TTL1, TTL2, not_found,
                  fun() -> ls_vm:get(Vm) end);
            _ ->
                ls_vm:get(Vm)
        end,
    ?MSniffle(?P(State), Start),
    R;

get(_State) ->
    not_found.


permission_required(put, [<<"dry_run">>], _) ->
    {ok, [<<"cloud">>, <<"vms">>, <<"create">>]};

permission_required(get, [], _) ->
    {ok, [<<"cloud">>, <<"vms">>, <<"list">>]};

permission_required(post, [], _) ->
    {ok, [<<"cloud">>, <<"vms">>, <<"create">>]};

permission_required(get, [?UUID(Vm)], _) ->
    {ok, [<<"vms">>, Vm, <<"get">>]};

permission_required(get, [?UUID(Vm), <<"metrics">> | _], _) ->
    {ok, [<<"vms">>, Vm, <<"get">>]};

permission_required(delete, [?UUID(Vm)], _) ->
    {ok, [<<"vms">>, Vm, <<"delete">>]};

permission_required(delete, [?UUID(Vm), <<"hypervisor">>], _) ->
    {ok, [<<"vms">>, Vm, <<"delete">>]};

permission_required(post, [?UUID(Vm), <<"nics">>], _) ->
    {ok, [<<"vms">>, Vm, <<"edit">>]};

permission_required(put, [?UUID(Vm), <<"nics">>, _], _) ->
    {ok, [<<"vms">>, Vm, <<"edit">>]};

permission_required(delete, [?UUID(Vm), <<"nics">>, _], _) ->
    {ok, [<<"vms">>, Vm, <<"edit">>]};

permission_required(post, [?UUID(Vm), <<"snapshots">>], _) ->
    {ok, [<<"vms">>, Vm, <<"snapshot">>]};

permission_required(post, [?UUID(Vm), <<"fw_rules">>], _) ->
    {ok, [<<"vms">>, Vm, <<"edit">>]};

permission_required(delete, [?UUID(Vm), <<"fw_rules">>, _FWID], _) ->
    {ok, [<<"vms">>, Vm, <<"edit">>]};

permission_required(put, [?UUID(Vm), <<"services">>], _) ->
    {ok, [<<"vms">>, Vm, <<"edit">>]};

permission_required(post, [?UUID(Vm), <<"backups">>], _) ->
    {ok, [<<"vms">>, Vm, <<"backup">>]};

permission_required(put, [?UUID(_Vm), <<"owner">>], #state{body = undefiend}) ->
    {error, needs_decode};

permission_required(put, [?UUID(Vm), <<"owner">>], #state{body = Decoded}) ->
    case Decoded of
        [{<<"org">>, Owner}] ->
            {multiple,
             [[<<"vms">>, Vm, <<"edit">>],
              [<<"orgs">>, Owner, <<"edit">>]]};
        _ ->
            {ok, [<<"vms">>, Vm, <<"edit">>]}
    end;

permission_required(put, _, #state{body = undefiend}) ->
    {error, needs_decode};

permission_required(put, [?UUID(_Vm), <<"state">>], #state{body = undefined}) ->
    {error, needs_decode};

permission_required(put, [?UUID(Vm), <<"state">>],
                    #state{body = [{<<"action">>, Act} | _]}) ->
    {ok, [<<"vms">>, Vm, Act]};


permission_required(put, [?UUID(Vm), <<"config">>], _ ) ->
    {ok, [<<"vms">>, Vm, <<"edit">>]};

permission_required(put, [?UUID(Vm), <<"package">>], _) ->
    {ok, [<<"vms">>, Vm, <<"edit">>]};

permission_required(put, [?UUID(Vm), <<"snapshots">>, _Snap],
                    #state{body = [{<<"action">>, <<"rollback">>}]}) ->
    {ok, [<<"vms">>, Vm, <<"rollback">>]};

permission_required(put, [?UUID(Vm), <<"snapshots">>, _Snap], _) ->
    {ok, [<<"vms">>, Vm, <<"edit">>]};

permission_required(delete, [?UUID(Vm), <<"snapshots">>, _Snap], _) ->
    {ok, [<<"vms">>, Vm, <<"snapshot_delete">>]};

permission_required(put, [?UUID(Vm), <<"backups">>, _Snap],
                    #state{body =[{<<"action">>, <<"rollback">>}|_]}) ->
    {ok, [<<"vms">>, Vm, <<"rollback">>]};


permission_required(put, [?UUID(Vm), <<"backups">>, _Snap], _) ->
    {ok, [<<"vms">>, Vm, <<"edit">>]};


permission_required(delete, [?UUID(Vm), <<"backups">>, _Snap], _) ->
    {ok, [<<"vms">>, Vm, <<"backup_delete">>]};

permission_required(put, [?UUID(Vm), <<"metadata">> | _], _) ->
    {ok, [<<"vms">>, Vm, <<"edit">>]};

permission_required(delete, [?UUID(Vm), <<"metadata">> | _], _) ->
    {ok, [<<"vms">>, Vm, <<"edit">>]};

permission_required(_Method, _Path, _State) ->
    undefined.


%%--------------------------------------------------------------------
%% Schema
%%--------------------------------------------------------------------

%% Creates a VM
schema(#state{method = <<"PUT">>, path = []}) ->
    vm_create;

%% Creates a snapshot
schema(#state{method = <<"PUT">>, path = [?UUID(_Vm), <<"snapshots">>]}) ->
    vm_snapshot;

%% Adds a firewall rule
schema(#state{method = <<"PUT">>, path = [?UUID(_Vm), <<"fw_rules">>]}) ->
    vm_fw_rule;

%% create a backup
schema(#state{method = <<"PUT">>, path = [?UUID(_Vm), <<"backups">>]}) ->
    vm_backup;

%% adds a nice
schema(#state{method = <<"PUT">>, path = [?UUID(_Vm), <<"nics">>]}) ->
    vm_add_nic;

%% Dry run
schema(#state{method = <<"POST">>, path = []}) ->
    vm_create;

%% Changes a VM state
schema(#state{method = <<"PUT">>, path = [?UUID(_Vm), <<"state">>],
              version = ?V2}) ->
    vm_update_state;


%% Updates a VM Config, we don't have validation that in the V! api
schema(#state{method = <<"PUT">>, path = [?UUID(_Vm), <<"config">>],
              version = ?V2}) ->
    vm_update_config;

schema(#state{method = <<"PUT">>, path = [?UUID(_Vm), <<"package">>],
              version = ?V2}) ->
    vm_update_package;

%% Snapshots
schema(#state{method = <<"POST">>,
              path = [?UUID(_Vm), <<"snapshots">>, ?UUID(_Snap)]}) ->
    vm_rollback_snapshot;

%% Backups
schema(#state{method = <<"POST">>,
              path = [?UUID(_Vm), <<"backups">>, ?UUID(_Backup)]}) ->
    vm_rollback_backup;

%% State change
schema(#state{method = <<"POST">>, path = [?UUID(_Vm), <<"services">>]}) ->
    vm_service_change;

schema(_State) ->
    none.

%%--------------------------------------------------------------------
%% GET
%%--------------------------------------------------------------------

read(Req, State = #state{token = Token, path = [], full_list=FullList,
                         full_list_fields=Filter}) ->
    Start = erlang:system_time(micro_seconds),
    {ok, Permissions} = wiggle_h:get_permissions(Token),
    ?MSnarl(?P(State), Start),
    Start1 = erlang:system_time(micro_seconds),
    Permission = [{must, 'allowed',
                   [<<"vms">>, {<<"res">>, <<"uuid">>}, <<"get">>],
                   Permissions}],
    Res = wiggle_h:list(fun ls_vm:list/2,
                        fun to_json/1, Token, Permission,
                        FullList, Filter, vm_list_ttl, ?FULL_CACHE,
                        ?LIST_CACHE),
    ?MSniffle(?P(State), Start1),
    {Res, Req, State};

read(Req, State = #state{path = [?UUID(_Vm)], obj = Obj}) ->
    {to_json(Obj), Req, State};

read(Req, State = #state{path = [?UUID(Vm), <<"metrics">>]}) ->
    {QS, Req1} = cowboy_req:qs_vals(Req),
    case perf(Vm, QS) of
        {ok, JSON} ->
            {JSON, Req1, State};
        {error, no_results} ->
            {ok, Req2} = cowboy_req:reply(
                           503, [], <<"Empty result set">>, Req1),
            {halt, Req2, State};
        {error, bad_qs} ->
            {ok, Req2} = cowboy_req:reply(
                           400, [], <<"bad qeruy string">>, Req1),
            {halt, Req2, State};
        {error, bad_resolution} ->
            {ok, Req2} = cowboy_req:reply(
                           400, [], <<"bad resolution">>, Req1),
            {halt, Req2, State}
    end.


%%--------------------------------------------------------------------
%% PUT
%%--------------------------------------------------------------------

create(Req, State = #state{path = [], version = Version, token = Token},
       Decoded) ->
    {ok, Dataset} = jsxd:get(<<"dataset">>, Decoded),
    {ok, Package} = jsxd:get(<<"package">>, Decoded),
    {ok, Config} = jsxd:get(<<"config">>, Decoded),
    %% If the creating user has advanced_create permissions they can pass
    %% 'requirements' as part of the config, if they lack the permission
    %% it simply gets removed.
    Config1 = case libsnarl:allowed(
                     Token,
                     [<<"cloud">>, <<"vms">>, <<"advanced_create">>]) of
                  true ->
                      Config;
                  _ ->
                      jsxd:set(<<"requirements">>, [], Config)
              end,
    try
        Start = erlang:system_time(micro_seconds),
        Config2 = jsxd:set(<<"owner">>, user(State), Config1),
        {ok, UUID} = ls_vm:create(Package, Dataset, Config2),
        e2qc:teardown(?LIST_CACHE),
        e2qc:teardown(?FULL_CACHE),
        ?MSniffle(?P(State), Start),
        {{true, <<"/api/", Version/binary, "/vms/", UUID/binary>>},
         Req, State#state{body = Decoded}}
    catch
        G:E ->
            lager:error("Error creating VM(~p): ~p / ~p", [Decoded, G, E]),
            {ok, Req1} = cowboy_req:reply(500, Req),
            {halt, Req1, State}
    end;

create(Req, State = #state{path = [?UUID(Vm), <<"snapshots">>],
                           version = Version}, Decoded) ->
    Comment = jsxd:get(<<"comment">>, <<"">>, Decoded),
    Start = erlang:system_time(micro_seconds),
    {ok, _UUID} = ls_vm:snapshot(Vm, Comment),
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {{true, <<"/api/", Version/binary, "/vms/", Vm/binary>>},
     Req, State#state{body = Decoded}};

create(Req, State = #state{path = [?UUID(Vm), <<"fw_rules">>],
                           version = Version}, RuleJSON) ->
    Start = erlang:system_time(micro_seconds),
    Rule = ft_vm:json_to_fw_rule(RuleJSON),
    ls_vm:add_fw_rule(Vm, Rule),
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {{true, <<"/api/", Version/binary, "/vms/", Vm/binary>>},
     Req, State#state{body = RuleJSON}};

create(Req, State = #state{path = [?UUID(Vm), <<"backups">>],
                          version = Version}, Decoded) ->
    Comment = jsxd:get(<<"comment">>, <<"">>, Decoded),
    Opts = [xml],
    Start = erlang:system_time(micro_seconds),
    case jsxd:get(<<"parent">>, Decoded) of
        {ok, Parent} ->
            Opts1 = case jsxd:get(<<"delete">>, false, Decoded) of
                        true ->
                            [{delete, parent} | Opts];
                        false ->
                            Opts
                    end,
            e2qc:evict(?CACHE, Vm),
            e2qc:teardown(?FULL_CACHE),
            {ok, _UUID} = ls_vm:incremental_backup(Vm, Parent, Comment,
                                                   Opts1);
        _ ->
            Opts1 = case jsxd:get(<<"delete">>, false, Decoded) of
                        true ->
                            [delete | Opts];
                        false ->
                            Opts
                    end,
            {ok, _UUID} = ls_vm:full_backup(Vm, Comment, Opts1)
    end,
    ?MSniffle(?P(State), Start),
    {{true, <<"/api/", Version/binary, "/vms/", Vm/binary>>},
     Req, State#state{body = Decoded}};


create(Req, State = #state{path = [?UUID(Vm), <<"nics">>], version = Version},
       [{<<"network">>, Network}]) ->
    Start = erlang:system_time(micro_seconds),
    case ls_vm:add_nic(Vm, Network) of
        ok ->
            ?MSniffle(?P(State), Start),
            e2qc:evict(?CACHE, Vm),
            e2qc:teardown(?FULL_CACHE),
            {{true, <<"/api/", Version/binary, "/vms/", Vm/binary>>},
             Req, State};
        {error, not_stopped} ->
            {ok, Req1} = cowboy_req:reply(412, [], <<"VM Running">>, Req),
            lager:error("Could not add nic, vm running."),
            {halt, Req1, State};
        E ->
            ?MSniffle(?P(State), Start),
            lager:error("Error adding nic to VM(~p) on network(~p) / ~p",
                        [?UUID(Vm), Network, E]),
            {ok, Req1} = cowboy_req:reply(500, Req),
            lager:error("Could not add nic: ~P"),
            {halt, Req1, State}
    end.


%%--------------------------------------------------------------------
%% POST
%%--------------------------------------------------------------------
-define(PWR2, State = #state{path = [?UUID(Vm), <<"state">>], version = ?V2}).

write(Req, State = #state{path = [<<"dry_run">>], token = Token}, Decoded) ->
    lager:info("Starting dryrun."),
    try
        {ok, Dataset} = jsxd:get(<<"dataset">>, Decoded),
        {ok, Package} = jsxd:get(<<"package">>, Decoded),
        {ok, Config} = jsxd:get(<<"config">>, Decoded),
        %% If the creating user has advanced_create permissions they can pass
        %% 'requirements' as part of the config, if they lack the permission
        %% it simply gets removed.
        Config1 = case libsnarl:allowed(
                         Token,
                         [<<"cloud">>, <<"vms">>, <<"advanced_create">>]) of
                      true ->
                          Config;
                      _ ->
                          jsxd:set(<<"requirements">>, [], Config)
                  end,
        try
            {ok, User} = ls_user:get(Token),
            Owner = ft_user:uuid(User),
            case ls_vm:dry_run(Package, Dataset,
                               jsxd:set(<<"owner">>, Owner, Config1)) of
                {ok, success} ->
                    {true, Req, State#state{body = Decoded}};
                E ->
                    lager:warning("Dry run failed with: ~p.", [E]),
                    {false, Req, State#state{body = Decoded}}
            end
        catch
            _G:_E ->
                {false, Req, State}
        end
    catch
        _G1:_E1 ->
            {false, Req, State}
    end;

write(Req, State = #state{path = [?UUID(Vm), <<"services">>]},
      [{<<"action">>, <<"enable">>},
       {<<"service">>, Service}]) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ls_vm:service_enable(Vm, Service),
    {true, Req, State};

write(Req, State = #state{path = [?UUID(Vm), <<"services">>]},
      [{<<"action">>, <<"disable">>},
       {<<"service">>, Service}]) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ls_vm:service_disable(Vm, Service),
    {true, Req, State};

write(Req, State = #state{path = [?UUID(Vm), <<"services">>]},
      [{<<"action">>, <<"clear">>},
       {<<"service">>, Service}]) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ls_vm:service_clear(Vm, Service),
    {true, Req, State};

write(Req, State = #state{path = [?UUID(Vm), <<"services">>]},
      [{<<"action">>, <<"refresh">>},
       {<<"service">>, Service}]) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ls_vm:service_refresh(Vm, Service),
    {true, Req, State};

write(Req, State = #state{path = [?UUID(Vm), <<"services">>]},
      [{<<"action">>, <<"restart">>},
       {<<"service">>, Service}]) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ls_vm:service_restart(Vm, Service),
    {true, Req, State};

write(Req, State = #state{path = [_, <<"nics">>]}, _Body) ->
    {true, Req, State};

write(Req, State = #state{path = [?UUID(Vm), <<"owner">>]},
      [{<<"org">>, Org}]) ->
    Start = erlang:system_time(micro_seconds),
    case ls_org:get(Org) of
        {ok, _} ->
            e2qc:evict(?CACHE, Vm),
            e2qc:teardown(?FULL_CACHE),
            R = ls_vm:owner(user(State), Vm, Org),
            ?MSniffle(?P(State), Start),
            {R =:= ok, Req, State};
        E ->
            ?MSniffle(?P(State), Start),
            lager:error("Error trying to assign org ~p since it does not "
                        "seem to exist", [Org]),
            {ok, Req1} = cowboy_req:reply(404, Req),
            lager:error("Could not change owner: ~p", [E]),
            {halt, Req1, State}
    end;

write(Req, State = #state{path = [?UUID(Vm), <<"nics">>, Mac]},
      [{<<"primary">>, true}]) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?LIB(ls_vm:primary_nic(Vm, Mac));

write(Req, State = #state{path = [?UUID(Vm), <<"metadata">> | Path]},
      [{K, V}]) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?LIB(ls_vm:set_metadata(Vm,  [{Path ++ [K],
                                   jsxd:from_list(V)}]));

%%--------------------------------------------------------------------
%% Power State Changes
%%--------------------------------------------------------------------

%% 0.2.0
write(Req, ?PWR2, [{<<"action">>, <<"start">>}]) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?LIB(ls_vm:start(Vm));

write(Req, ?PWR2, [{<<"action">>, <<"stop">>}]) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?LIB(ls_vm:stop(Vm));

write(Req, ?PWR2, [{<<"action">>, <<"stop">>}, {<<"force">>, true}]) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?LIB(ls_vm:stop(Vm, [force]));

write(Req, ?PWR2, [{<<"action">>, <<"reboot">>}]) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?LIB(ls_vm:reboot(Vm));

write(Req, ?PWR2, [{<<"action">>, <<"reboot">>}, {<<"force">>, true}]) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?LIB(ls_vm:reboot(Vm, [force]));

%%--------------------------------------------------------------------
%% VM Update
%%--------------------------------------------------------------------

%% 0.2.0
write(Req, State = #state{path = [?UUID(Vm), <<"config">>], version = ?V2},
      Config) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?LIB(ls_vm:update(user(State), Vm, undefined, Config));

write(Req, State = #state{path = [?UUID(Vm), <<"package">>], version = ?V2},
      [{<<"package">>, Package}]) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?LIB(ls_vm:update(user(State), Vm, Package, []));

%%--------------------------------------------------------------------
%% Snapshots
%%--------------------------------------------------------------------

write(Req, State = #state{path = [?UUID(Vm), <<"snapshots">>, UUID]},
      [{<<"action">>, <<"rollback">>}]) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?LIB(ls_vm:rollback_snapshot(Vm, UUID));

%%--------------------------------------------------------------------
%% backups
%%--------------------------------------------------------------------
write(Req, State = #state{path = [?UUID(Vm), <<"backups">>, UUID]},
      [{<<"action">>, <<"rollback">>},
       {<<"hypervisor">>, Hypervisor}]) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?LIB(ls_vm:restore_backup(user(State), Vm, UUID, Hypervisor));

write(Req, State = #state{path = [?UUID(Vm), <<"backups">>, UUID]},
      [{<<"action">>, <<"rollback">>}]) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?LIB(ls_vm:restore_backup(Vm, UUID));

write(Req, State, _Body) ->
    lager:error("Unknown PUT request: ~p~n.", [State]),
    {false, Req, State}.

%%--------------------------------------------------------------------
%% DEETE
%%--------------------------------------------------------------------

delete(Req, State = #state{path = [?UUID(Vm), <<"snapshots">>, UUID]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_vm:delete_snapshot(Vm, UUID),
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

delete(Req, State = #state{path = [?UUID(Vm), <<"fw_rules">>, RuleIDs],
                           obj = Obj}) ->
    Start = erlang:system_time(micro_seconds),
    RuleID = binary_to_integer(RuleIDs),
    {ok, Rule} = find_rule(RuleID, Obj),
    ok = ls_vm:remove_fw_rule(Vm, Rule),
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

delete(Req, State = #state{path = [?UUID(Vm), <<"backups">>, UUID],
                           body=[{<<"location">>, <<"hypervisor">>}]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_vm:delete_backup(Vm, UUID, hypervisor),
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

delete(Req, State = #state{path = [?UUID(Vm), <<"backups">>, UUID]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_vm:delete_backup(Vm, UUID, cloud),
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

delete(Req, State = #state{path = [?UUID(Vm), <<"nics">>, Mac]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_vm:remove_nic(Vm, Mac),
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

delete(Req, State = #state{path = [?UUID(Vm)],
                           body=[{<<"location">>, <<"hypervisor">>}]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_vm:store(user(State), Vm),
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

delete(Req, State = #state{path = [?UUID(Vm), <<"hypervisor">>]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_vm:store(user(State), Vm),
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

delete(Req, State = #state{path = [?UUID(Vm)]}) ->
    Start = erlang:system_time(micro_seconds),
    case ls_vm:delete(user(State), Vm) of
        ok ->
            e2qc:evict(?CACHE, Vm),
            e2qc:teardown(?LIST_CACHE),
            e2qc:teardown(?FULL_CACHE),
            ?MSniffle(?P(State), Start),
            {true, Req, State};
        {error, creating} ->
            {ok, Req1} = cowboy_req:reply(423, Req),
            lager:error("Could not delete: locked"),
            {halt, Req1, State}
    end;

delete(Req, State = #state{path = [?UUID(Vm), <<"metadata">> | Path]}) ->
    Start = erlang:system_time(micro_seconds),
    ls_vm:set_metadata(Vm, [{Path, delete}]),
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {true, Req, State}.

user(#state{token = Token}) ->
    {ok, User} = ls_user:get(Token),
    ft_user:uuid(User).

to_json(VM) ->
    jsxd:update(<<"fw_rules">>,
                fun (Rules) ->
                        [ [{<<"id">>, erlang:phash2(Rule)} | Rule] ||
                            Rule <- Rules]
                end, ft_vm:to_json(VM)).

find_rule(ID, VM) ->
    Rules = jsxd:get(<<"fw_rules">>, [], ft_vm:to_json(VM)),
    Found = lists:filter(fun(Rule) ->
                                 ID == erlang:phash2(Rule)
                         end, Rules),
    case Found of
        [Rule] ->
            {ok, ft_vm:json_to_fw_rule(Rule)};
        _ ->
            {error, oh_shit}
    end.

%%--------------------------------------------------------------------
%% Internal
%%--------------------------------------------------------------------

perf(UUID, QS) ->
    Zone = wiggle_metrics:short_id(UUID),
    Elems = perf_cpu(Zone) ++ perf_mem(Zone) ++ perf_swap(Zone)
        ++ perf_net(Zone, <<"net0">>) ++ perf_zfs(Zone),
    wiggle_metrics:get(Elems, QS).

perf_cpu(Zone) ->
    [{"cpu-usage",     z([Zone, cpu, usage])},
     {"cpu-effective", z([Zone, cpu, effective])},
     {"cpu-nwait",     z([Zone, cpu, effective])}].

perf_mem(Zone) ->
    [{"memory-usage", mb([Zone, mem, usage])},
     {"memory-value", mb([Zone, mem, value])}].

perf_swap(Zone) ->
    [{"swap-usage", mb([Zone, swap, usage])},
     {"swap-value", mb([Zone, swap, value])}].

perf_net(Zone, Nic) ->
    [{["net-send-ops-", Nic], der([Zone, net, Nic, opackets64])},
     {["net-recv-ops-", Nic], der([Zone, net, Nic, ipackets64])},
     {["net-send-kb-", Nic],  der([Zone, net, Nic, obytes64])},
     {["net-recv-kb-", Nic],  der([Zone, net, Nic, ubytes64])}].


perf_zfs(Zone) ->
    [{"zfs-read-kb",  {f, divide, [der([Zone, zfs, nread]), 1024]}},
     {"zfs-write-kb", {f, divide, [der([Zone, zfs, nwritten]), 1024]}},
     {"zfs-read-ops", der([Zone, zfs, reads])},
     {"zfs-write-ops", der([Zone, zfs, writes])}].

z(L) ->
    {m, zone, L}.

mb(L) ->
    wiggle_metrics:mb(z(L)).

der(L) ->
    wiggle_metrics:der(z(L)).
