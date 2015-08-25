-module(wiggle_vm_h).

-include("wiggle.hrl").

-define(CACHE, vm).
-define(LIST_CACHE, vm_list).
-define(FULL_CACHE, vm_full_list).

-export([allowed_methods/3,
         get/1,
         permission_required/1,
         read/2,
         create/3,
         write/3,
         delete/2,
         schema/1]).

-ignore_xref([schema/1]).

-behaviour(wiggle_rest_h).

-define(GUARD_CALL(Call),
        case Call of
            ok ->
                true;
            GuardCallError ->
                lager:error("Error: ~p", [GuardCallError]),
                false
        end).

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

allowed_methods(?V1, _Token, [?UUID(_Vm), <<"services">>]) ->
    [<<"PUT">>, <<"GET">>];

allowed_methods(_Version, _Token, [?UUID(_Vm), <<"services">>]) ->
    [<<"PUT">>];

allowed_methods(_Version, _Token, [?UUID(_Vm), <<"metadata">>|_]) ->
    [<<"PUT">>, <<"DELETE">>];

allowed_methods(_Version, _Token, [?UUID(_Vm), <<"nics">>, _Mac]) ->
    [<<"PUT">>, <<"DELETE">>];

allowed_methods(_Version, _Token, [?UUID(_Vm), <<"nics">>]) ->
    [<<"POST">>];

allowed_methods(?V1, _Token, [?UUID(_Vm), <<"snapshots">>, _ID]) ->
    [<<"GET">>, <<"PUT">>, <<"DELETE">>];

allowed_methods(_Version, _Token, [?UUID(_Vm), <<"snapshots">>, _ID]) ->
    [<<"PUT">>, <<"DELETE">>];

allowed_methods(?V1, _Token, [?UUID(_Vm), <<"snapshots">>]) ->
    [<<"GET">>, <<"POST">>];

allowed_methods(_Version, _Token, [?UUID(_Vm), <<"snapshots">>]) ->
    [<<"POST">>];

allowed_methods(?V1, _Token, [?UUID(_Vm), <<"fw_rules">>, _ID]) ->
    [<<"GET">>, <<"DELETE">>]; %% We might need to add PUT later.

allowed_methods(_Version, _Token, [?UUID(_Vm), <<"fw_rules">>, _ID]) ->
    [<<"DELETE">>]; %% We might need to add PUT later.

allowed_methods(?V1, _Token, [?UUID(_Vm), <<"fw_rules">>]) ->
    [<<"GET">>, <<"POST">>];

allowed_methods(_Version, _Token, [?UUID(_Vm), <<"fw_rules">>]) ->
    [<<"POST">>];

allowed_methods(?V1, _Token, [?UUID(_Vm), <<"backups">>, _ID]) ->
    [<<"GET">>, <<"PUT">>, <<"DELETE">>];

allowed_methods(_Version, _Token, [?UUID(_Vm), <<"backups">>, _ID]) ->
    [<<"PUT">>, <<"DELETE">>];

allowed_methods(?V1, _Token, [?UUID(_Vm), <<"backups">>]) ->
    [<<"POST">>];

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


permission_required(#state{method = <<"PUT">>, path = [<<"dry_run">>]}) ->
    {ok, [<<"cloud">>, <<"vms">>, <<"create">>]};

permission_required(#state{method = <<"GET">>, path = []}) ->
    {ok, [<<"cloud">>, <<"vms">>, <<"list">>]};

permission_required(#state{method = <<"POST">>, path = []}) ->
    {ok, [<<"cloud">>, <<"vms">>, <<"create">>]};

permission_required(#state{method = <<"GET">>, path = [?UUID(Vm)]}) ->
    {ok, [<<"vms">>, Vm, <<"get">>]};

permission_required(#state{version = ?V2, method = <<"GET">>,
                           path = [?UUID(Vm), <<"metrics">> | _]}) ->
    {ok, [<<"vms">>, Vm, <<"get">>]};

permission_required(#state{method = <<"DELETE">>, path = [?UUID(Vm)]}) ->
    {ok, [<<"vms">>, Vm, <<"delete">>]};

permission_required(#state{method = <<"DELETE">>, path = [?UUID(Vm), <<"hypervisor">>]}) ->
    {ok, [<<"vms">>, Vm, <<"delete">>]};

permission_required(#state{method = <<"POST">>, path = [?UUID(Vm), <<"nics">>]}) ->
    {ok, [<<"vms">>, Vm, <<"edit">>]};

permission_required(#state{method = <<"PUT">>, path = [?UUID(Vm), <<"nics">>, _]}) ->
    {ok, [<<"vms">>, Vm, <<"edit">>]};

permission_required(#state{method = <<"DELETE">>, path = [?UUID(Vm), <<"nics">>, _]}) ->
    {ok, [<<"vms">>, Vm, <<"edit">>]};

permission_required(#state{version=?V1, method = <<"GET">>,
                           path = [?UUID(Vm), <<"snapshots">>]}) ->
    {ok, [<<"vms">>, Vm, <<"get">>]};

permission_required(#state{method = <<"POST">>, path = [?UUID(Vm), <<"snapshots">>]}) ->
    {ok, [<<"vms">>, Vm, <<"snapshot">>]};

permission_required(#state{version=?V1, method = <<"GET">>,
                           path = [?UUID(Vm), <<"fw_rules">>]}) ->
    {ok, [<<"vms">>, Vm, <<"get">>]};

permission_required(#state{method = <<"POST">>, path = [?UUID(Vm), <<"fw_rules">>]}) ->
    {ok, [<<"vms">>, Vm, <<"edit">>]};

permission_required(#state{method = <<"DELETE">>, path = [?UUID(Vm), <<"fw_rules">>, _FWID]}) ->
    {ok, [<<"vms">>, Vm, <<"edit">>]};

permission_required(#state{version=?V1, method = <<"GET">>,
                           path = [?UUID(Vm), <<"services">>]}) ->
    {ok, [<<"vms">>, Vm, <<"get">>]};

permission_required(#state{method = <<"PUT">>, path = [?UUID(Vm), <<"services">>]}) ->
    {ok, [<<"vms">>, Vm, <<"edit">>]};

permission_required(#state{version=?V1, method = <<"GET">>,
                           path = [?UUID(Vm), <<"snapshots">>, _Snap]}) ->
    {ok, [<<"vms">>, Vm, <<"get">>]};

permission_required(#state{version=?V1, method = <<"GET">>,
                           path = [?UUID(Vm), <<"backups">>]}) ->
    {ok, [<<"vms">>, Vm, <<"get">>]};

permission_required(#state{method = <<"POST">>, path = [?UUID(Vm), <<"backups">>]}) ->
    {ok, [<<"vms">>, Vm, <<"backup">>]};

permission_required(#state{version=?V1, method = <<"GET">>,
                           path = [?UUID(Vm), <<"backups">>, _Snap]}) ->
    {ok, [<<"vms">>, Vm, <<"get">>]};

permission_required(#state{method = <<"PUT">>, path = [?UUID(_Vm), <<"owner">>], body = undefiend}) ->
    {error, needs_decode};

permission_required(#state{method = <<"PUT">>, path = [?UUID(Vm), <<"owner">>], body = Decoded}) ->
    case Decoded of
        [{<<"org">>, Owner}] ->
            {multiple,
             [[<<"vms">>, Vm, <<"edit">>],
              [<<"orgs">>, Owner, <<"edit">>]]};
        _ ->
            {ok, [<<"vms">>, Vm, <<"edit">>]}
    end;

permission_required(#state{method = <<"PUT">>, body = undefiend}) ->
    {error, needs_decode};

permission_required(#state{method = <<"PUT">>, body = Decoded, version = ?V1,
                           path = [?UUID(Vm)]}) ->
    case Decoded of
        [{<<"action">>, Act} | _] ->
            {ok, [<<"vms">>, Vm, Act]};
        _ ->
            {ok, [<<"vms">>, Vm, <<"edit">>]}

    end;

permission_required(#state{method = <<"PUT">>, body = undefined,
                           version = ?V2, path = [?UUID(_Vm), <<"state">>]}) ->
    {error, needs_decode};

permission_required(#state{method = <<"PUT">>, body = [{<<"action">>, Act} | _],
                           version = ?V2, path = [?UUID(Vm), <<"state">>]}) ->
    {ok, [<<"vms">>, Vm, Act]};


permission_required(#state{method = <<"PUT">>, version = ?V2,
                           path = [?UUID(Vm), <<"config">>]}) ->
    {ok, [<<"vms">>, Vm, <<"edit">>]};

permission_required(#state{method = <<"PUT">>, version = ?V2,
                           path = [?UUID(Vm), <<"package">>]}) ->
    {ok, [<<"vms">>, Vm, <<"edit">>]};

permission_required(#state{method = <<"PUT">>, body = Decoded,
                           path = [?UUID(Vm), <<"snapshots">>, _Snap]}) ->
    case Decoded of
        [{<<"action">>, <<"rollback">>}] ->
            {ok, [<<"vms">>, Vm, <<"rollback">>]};
        _ ->
            {ok, [<<"vms">>, Vm, <<"edit">>]}
    end;

permission_required(#state{method = <<"DELETE">>, path = [?UUID(Vm), <<"snapshots">>, _Snap]}) ->
    {ok, [<<"vms">>, Vm, <<"snapshot_delete">>]};

permission_required(#state{method = <<"PUT">>, body = Decoded,
                           path = [?UUID(Vm), <<"backups">>, _Snap]}) ->
    case Decoded of
        [{<<"action">>, <<"rollback">>}|_] ->
            {ok, [<<"vms">>, Vm, <<"rollback">>]};
        _ ->
            {ok, [<<"vms">>, Vm, <<"edit">>]}
    end;

permission_required(#state{method = <<"DELETE">>, path = [?UUID(Vm), <<"backups">>, _Snap]}) ->
    {ok, [<<"vms">>, Vm, <<"backup_delete">>]};

permission_required(#state{method = <<"PUT">>,
                           path = [?UUID(Vm), <<"metadata">> | _]}) ->
    {ok, [<<"vms">>, Vm, <<"edit">>]};

permission_required(#state{method = <<"DELETE">>, path = [?UUID(Vm), <<"metadata">> | _]}) ->
    {ok, [<<"vms">>, Vm, <<"edit">>]};

permission_required(_State) ->
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


%% Dry Run
schema(#state{method = <<"POST">>, path = [?UUID(_Vm), <<"services">>]}) ->
    vm_service_change;

schema(_State) ->
    none.

%%--------------------------------------------------------------------
%% GET
%%--------------------------------------------------------------------

read(Req, State = #state{token = Token, path = [], full_list=FullList, full_list_fields=Filter}) ->
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

read(Req, State = #state{version=?V1, path = [?UUID(_Vm), <<"snapshots">>], obj = Obj}) ->
    Snaps = jsxd:fold(fun(UUID, Snap, Acc) ->
                              [jsxd:set(<<"uuid">>, UUID, Snap) | Acc]
                      end, [], ft_vm:snapshots(Obj)),
    {Snaps, Req, State};

read(Req, State = #state{version=?V1, path = [?UUID(_Vm), <<"snapshots">>, SnapID], obj = Obj}) ->
    case jsxd:get([SnapID], ft_vm:snapshots(Obj)) of
        {ok, SnapObj} ->
            {jsxd:set(<<"uuid">>, SnapID, SnapObj), Req, State};
        _ ->
            {null, Req, State}

    end;

read(Req, State = #state{version=?V1, path = [?UUID(_Vm), <<"backups">>], obj = Obj}) ->
    Snaps = jsxd:fold(fun(UUID, Snap, Acc) ->
                              [jsxd:set(<<"uuid">>, UUID, Snap) | Acc]
                      end, [], ft_vm:backups(Obj)),
    {Snaps, Req, State};

read(Req, State = #state{version=?V1, path = [?UUID(_Vm), <<"backups">>, SnapID], obj = Obj}) ->
    case jsxd:get([SnapID], ft_vm:backups(Obj)) of
        {ok, SnapObj} ->
            {jsxd:set(<<"uuid">>, SnapID, SnapObj), Req, State};
        _ ->
            {null, Req, State}
    end;

read(Req, State = #state{version=?V1, path = [?UUID(_Vm), <<"services">>], obj = Obj}) ->
    {ft_vm:services(Obj), Req, State};

read(Req, State = #state{version=?V1, path = [?UUID(_Vm), <<"services">>, Service], obj = Obj}) ->
    {jsxd:get([Service], [{}], ft_vm:services(Obj)), Req, State};

read(Req, State = #state{path = [?UUID(_Vm)], obj = Obj}) ->
    {to_json(Obj), Req, State};

read(Req, State = #state{path = [?UUID(Vm), <<"metrics">>]}) ->
    {QS, Req1} = cowboy_req:qs_vals(Req),
    {ok, Q} = perf(Vm, lists:sort(QS)),
    lager:debug("[metrics] Running query ~s", [Q]),
    {T, {ok, _T0, Res}} = timer:tc(dqe, run, [Q]),
    lager:debug("[metrics] The query took ~pus", [T]),
    JSON = [[{<<"n">>, Name},
             {<<"r">>, Resolution},
             {<<"v">>, mmath_bin:to_list(Data)}]
            || {Name, Data, Resolution} <- Res],

    {JSON, Req1, State}.


%%--------------------------------------------------------------------
%% PUT
%%--------------------------------------------------------------------

create(Req, State = #state{path = [], version = Version, token = Token}, Decoded) ->
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
        {ok, UUID} = ls_vm:create(Package, Dataset, jsxd:set(<<"owner">>, user(State), Config1)),
        e2qc:teardown(?LIST_CACHE),
        e2qc:teardown(?FULL_CACHE),
        ?MSniffle(?P(State), Start),
        {{true, <<"/api/", Version/binary, "/vms/", UUID/binary>>}, Req, State#state{body = Decoded}}
    catch
        G:E ->
            lager:error("Error creating VM(~p): ~p / ~p", [Decoded, G, E]),
            {ok, Req1} = cowboy_req:reply(500, Req),
            {halt, Req1, State}
    end;

create(Req, State = #state{path = [?UUID(Vm), <<"snapshots">>], version = Version}, Decoded) ->
    Comment = jsxd:get(<<"comment">>, <<"">>, Decoded),
    Start = erlang:system_time(micro_seconds),
    {ok, _UUID} = ls_vm:snapshot(Vm, Comment),
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {{true, <<"/api/", Version/binary, "/vms/", Vm/binary>>}, Req, State#state{body = Decoded}};

create(Req, State = #state{path = [?UUID(Vm), <<"fw_rules">>],
                           version = Version}, RuleJSON) ->
    Start = erlang:system_time(micro_seconds),
    Rule = ft_vm:json_to_fw_rule(RuleJSON),
    ls_vm:add_fw_rule(Vm, Rule),
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {{true, <<"/api/", Version/binary, "/vms/", Vm/binary>>}, Req, State#state{body = RuleJSON}};

create(Req, State = #state{path = [?UUID(Vm), <<"backups">>], version = Version}, Decoded) ->
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
    {{true, <<"/api/", Version/binary, "/vms/", Vm/binary>>}, Req, State#state{body = Decoded}};


create(Req, State = #state{path = [?UUID(Vm), <<"nics">>], version = Version},
       [{<<"network">>, Network}]) ->
    Start = erlang:system_time(micro_seconds),
    case ls_vm:add_nic(Vm, Network) of
        ok ->
            ?MSniffle(?P(State), Start),
            e2qc:evict(?CACHE, Vm),
            e2qc:teardown(?FULL_CACHE),
            {{true, <<"/api/", Version/binary, "/vms/", Vm/binary>>}, Req, State};
        {error, not_stopped} ->
            {ok, Req1} = cowboy_req:reply(412, [], <<"VM Running">>, Req),
            lager:error("Could not add nic, vm running."),
            {halt, Req1, State};
        E ->
            ?MSniffle(?P(State), Start),
            lager:error("Error adding nic to VM(~p) on network(~p) / ~p", [?UUID(Vm), Network, E]),
            {ok, Req1} = cowboy_req:reply(500, Req),
            lager:error("Could not add nic: ~P"),
            {halt, Req1, State}
    end.


%%--------------------------------------------------------------------
%% POST
%%--------------------------------------------------------------------
-define(PWR1, State = #state{path = [?UUID(Vm)], version = ?V1}).
-define(PWR2, State = #state{path = [?UUID(Vm), <<"state">>], version = ?V2}).
-define(UPD1, State = #state{path = [?UUID(Vm)], version = ?V1}).

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

write(Req, State = #state{path = [?UUID(Vm), <<"owner">>]}, [{<<"org">>, Org}]) ->
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

write(Req, State = #state{path = [?UUID(Vm), <<"nics">>, Mac]}, [{<<"primary">>, true}]) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?LIB(ls_vm:primary_nic(Vm, Mac));

write(Req, State = #state{path = [?UUID(Vm), <<"metadata">> | Path]}, [{K, V}]) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?LIB(ls_vm:set_metadata(Vm,  [{Path ++ [K],
                                   jsxd:from_list(V)}]));

%%--------------------------------------------------------------------
%% Power State Changes
%%--------------------------------------------------------------------

%% 0.1.0
write(Req, ?PWR1, [{<<"action">>, <<"start">>}]) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?LIB(ls_vm:start(Vm));

write(Req, ?PWR1, [{<<"action">>, <<"stop">>}]) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?LIB(ls_vm:stop(Vm));

write(Req, ?PWR1, [{<<"action">>, <<"stop">>}, {<<"force">>, true}]) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?LIB(ls_vm:stop(Vm, [force]));

write(Req, ?PWR1, [{<<"action">>, <<"reboot">>}]) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?LIB(ls_vm:reboot(Vm));

write(Req, ?PWR1, [{<<"action">>, <<"reboot">>}, {<<"force">>, true}]) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?LIB(ls_vm:reboot(Vm, [force]));

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

%% 0.1.0
write(Req, ?UPD1, [{<<"config">>, Config}, {<<"package">>, Package}]) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?LIB(ls_vm:update(user(State), Vm, Package, Config));

write(Req, ?UPD1, [{<<"config">>, Config}]) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?LIB(ls_vm:update(user(State), Vm, undefined, Config));

write(Req, ?UPD1, [{<<"package">>, Package}]) ->
    e2qc:evict(?CACHE, Vm),
    e2qc:teardown(?FULL_CACHE),
    ?LIB(ls_vm:update(user(State), Vm, Package, []));

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
        {error,creating} ->
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

valid_time(_Time) ->
    true. %% TODO!

valid_pit(_PIT) ->
    true. %% TODO

perf(UUID, QS) ->
    Zone = perf_zone_id(UUID),
    Elems = perf_cpu(Zone) ++ perf_mem(Zone) ++ perf_swap(Zone)
        ++ perf_net(Zone, <<"net0">>) ++ perf_zfs(Zone),
    case lists:keytake(<<"aggr">>, 1, QS) of
        false ->
            perf1(Elems, QS);
        {value, {<<"aggr">>, Res}, QS1} ->
            case valid_time(Res) of
                true ->
                    Elems1 = apply_aggr("avg", Res, Elems),
                    perf1(Elems1, QS1);
                false ->
                    {error, bad_resolution}
            end
    end.

perf1(Elems, [{<<"last">>, Last}]) ->
    case valid_time(Last) of
        true ->
            {ok, apply_query(Elems, ["LAST ", Last])};
        false ->
            {error, bad_last}
    end;


perf1(Elems, [{<<"after">>, After}, {<<"for">>, For}]) ->
    case valid_pit(After) andalso valid_time(For) of
        true ->
            {ok, apply_query(Elems, ["AFTER ", After, " FOR ", For])};
        false ->
            {error, bad_after}
    end;

perf1(Elems, [{<<"before">>, Before}, {<<"for">>, For}]) ->
    case valid_pit(Before) andalso valid_time(For) of
        true ->
            {ok, apply_query(Elems, ["BEFORE ", Before, " FOR ", For])};
        false ->
            {error, bad_before}
    end;


perf1(Elems, []) ->
    {ok, apply_query(Elems, "LAST 1m")};

perf1(_Elems, _) ->
    {error, bad_qs}.

perf_zone_id(<<Z:30/binary, _/binary>>) ->
    Z.

perf_cpu(Zone) ->
    [{[$', Zone | "'.'cpu'.'usage' BUCKET zone"], "cpu-usage"},
     {[$', Zone | "'.'cpu'.'effective' BUCKET zone"], "cpu-effective"},
     {[$', Zone | "'.'cpu'.'nwait' BUCKET zone"], "cpu-nwait"}].


perf_mem(Zone) ->
    [{[$', Zone | "'.'mem'.'usage' BUCKET zone"], "memory-usage"},
     {[$', Zone | "'.'mem'.'value' BUCKET zone"], "memory-value"}].


perf_swap(Zone) ->
    [{[$', Zone | "'.'swap'.'usage' BUCKET zone"], "swapory-usage"},
     {[$', Zone | "'.'swap'.'value' BUCKET zone"], "swapory-value"}].


perf_net(Zone, Nic) ->
    [{["derivate('", Zone, "'.'net'.'", Nic, "'.'opackets64' BUCKET zone)"],
      ["net-send-ops-", Nic]},
     {["derivate('", Zone, "'.'net'.'", Nic, "'.'ipackets64' BUCKET zone)"],
      ["net-recv-ops-", Nic]},
     {["divide(derivate('", Zone, "'.'net'.'", Nic, "'.'obytes64' BUCKET zone), 1024)"],
      ["net-send-kb-", Nic]},
     {["divide(derivate('", Zone, "'.'net'.'", Nic, "'.'rbytes64' BUCKET zone), 1024)"],
      ["net-recv-kb-", Nic]}].

perf_zfs(Zone) ->
    [{["divide(derivate('", Zone, "'.'zfs'.'nread' BUCKET zone), 1024)"], "zfs-read-kb"},
     {["divide(derivate('", Zone, "'.'zfs'.'nwritten' BUCKET zone), 1024)"], "zfs-write-kb"},
     {["derivate('", Zone, "'.'zfs'.'reads' BUCKET zone)"], "zfs-read-ops"},
     {["derivate('", Zone, "'.'zfs'.'writes' BUCKET zone)"], "zfs-write-ops"}].

apply_aggr(Aggr, Res, Elements) ->
    [{[Aggr, $(, Qry, ", ", Res, $)], Alias} ||
        {Qry, Alias} <- Elements].


apply_query(Elements, Range) ->
    Elements1 = [[Qry, " AS '", Alias, "'"] || {Qry, Alias} <- Elements],
    iolist_to_binary(["SELECT ", string:join(Elements1, ", "), " ", Range]).
