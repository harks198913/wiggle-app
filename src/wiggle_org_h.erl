-module(wiggle_org_h).
-include("wiggle.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-define(CACHE, org).
-define(LIST_CACHE, org_list).
-define(FULL_CACHE, org_full_list).

-export([allowed_methods/3,
         get/1,
         permission_required/1,
         read/2,
         create/3,
         write/3,
         delete/2]).

-behaviour(wiggle_rest_h).

allowed_methods(_Version, _Token, []) ->
    [<<"GET">>, <<"POST">>];

allowed_methods(_Version, _Token, [?UUID(_Org)]) ->
    [<<"GET">>, <<"PUT">>, <<"DELETE">>];

allowed_methods(?V1, _Token, [?UUID(_Org), <<"triggers">>]) ->
    [<<"GET">>];

allowed_methods(?V2, _Token, [?UUID(_Org), <<"accounting">>]) ->
    [<<"GET">>];

allowed_methods(_Version, _Token, [?UUID(_Org), <<"triggers">> | _Trigger]) ->
    [<<"POST">>, <<"DELETE">>];

allowed_methods(_Version, _Token, [?UUID(_Org), <<"metadata">> | _]) ->
    [<<"PUT">>, <<"DELETE">>].

get(State = #state{path = [?UUID(Org) | _]}) ->
    Start = erlang:system_time(micro_seconds),
    R = case application:get_env(wiggle, org_ttl) of
            {ok, {TTL1, TTL2}} ->
                wiggle_h:timeout_cache_with_invalid(
                  ?CACHE, Org, TTL1, TTL2, not_found,
                  fun() -> ls_org:get(Org) end);
            _ ->
                ls_org:get(Org)
        end,
    ?MSnarl(?P(State), Start),
    R;

get(_State) ->
    not_found.

permission_required(#state{method = <<"GET">>, path = []}) ->
    {ok, [<<"cloud">>, <<"orgs">>, <<"list">>]};

permission_required(#state{method = <<"POST">>, path = []}) ->
    {ok, [<<"cloud">>, <<"orgs">>, <<"create">>]};

permission_required(#state{method = <<"GET">>, path = [?UUID(Org)]}) ->
    {ok, [<<"orgs">>, Org, <<"get">>]};

permission_required(#state{method = <<"GET">>,
                           path = [?UUID(Org), <<"accounting">>]}) ->
    {ok, [<<"orgs">>, Org, <<"get">>]};

permission_required(#state{method = <<"PUT">>, path = [?UUID(Org)]}) ->
    {ok, [<<"orgs">>, Org, <<"create">>]};

permission_required(#state{method = <<"DELETE">>, path = [?UUID(Org)]}) ->
    {ok, [<<"orgs">>, Org, <<"delete">>]};

permission_required(#state{version = ?V1, method = <<"GET">>,
                           path = [?UUID(Org), <<"triggers">>]}) ->
    {ok, [<<"orgs">>, Org, <<"get">>]};

permission_required(#state{method = <<"POST">>,
                           path = [?UUID(_Org), <<"triggers">> | _],
                           body = undefined}) ->
    {error, needs_decode};

permission_required(#state{method = <<"POST">>,
                           path = [?UUID(Org), <<"triggers">> | _],
                           body = [{<<"action">>, <<"role_grant">>},
                                   {<<"base">>, _},
                                   {<<"permission">>, _},
                                   {<<"target">>, Role}]}) ->
    {multiple, [[<<"orgs">>, Org, <<"edit">>],
                [<<"roles">>, Role, <<"grant">>]]};

permission_required(#state{method = <<"POST">>,
                           path = [?UUID(Org), <<"triggers">> | _],
                           body = [{<<"action">>, <<"user_grant">>},
                                   {<<"base">>, _Base},
                                   {<<"permission">>, _Permission},
                                   {<<"target">>, User}]}) ->
    {multiple, [[<<"orgs">>, Org, <<"edit">>],
                [<<"users">>, User, <<"grant">>]]};

permission_required(#state{method = <<"POST">>,
                           path = [?UUID(Org), <<"triggers">> | _],
                           body = [{<<"action">>, <<"join_role">>},
                                   {<<"target">>, Role}]}) ->
    {multiple, [[<<"orgs">>, Org, <<"edit">>],
                [<<"roles">>, Role, <<"join">>]]};

permission_required(#state{
                       method = <<"POST">>,
                       path = [?UUID(Org), <<"triggers">> | _],
                       body = ([{<<"action">>, <<"join_org">>},
                                {<<"target">>, TargetOrg}])}) ->
    {multiple, [[<<"orgs">>, Org, <<"edit">>],
                [<<"orgs">>, TargetOrg, <<"join">>]]};

permission_required(#state{method = <<"DELETE">>,
                           path = [?UUID(Org), <<"triggers">> | _]}) ->
    {ok, [<<"orgs">>, Org, <<"edit">>]};

permission_required(#state{method = <<"PUT">>,
                           path = [?UUID(Org), <<"metadata">> | _]}) ->
    {ok, [<<"orgs">>, Org, <<"edit">>]};

permission_required(#state{method = <<"DELETE">>,
                           path = [?UUID(Org), <<"metadata">> | _]}) ->
    {ok, [<<"orgs">>, Org, <<"edit">>]};

permission_required(State) ->
    lager:warning("Unknown permission request: ~p.", [State]),
    undefined.

%%--------------------------------------------------------------------
%% GET
%%--------------------------------------------------------------------

read(Req, State = #state{token = Token, path = [], full_list=FullList, full_list_fields=Filter}) ->
    Start = erlang:system_time(micro_seconds),
    {ok, Permissions} = wiggle_h:get_permissions(Token),
    ?MSnarl(?P(State), Start),
    Start1 = erlang:system_time(micro_seconds),
    Permission = [{must, 'allowed',
                   [<<"orgs">>, {<<"res">>, <<"uuid">>}, <<"get">>],
                   Permissions}],
    Res = wiggle_h:list(fun ls_org:list/2,
                        fun to_json/1, Token, Permission,
                        FullList, Filter, org_list_ttl, ?FULL_CACHE,
                        ?LIST_CACHE),

    ?MSnarl(?P(State), Start1),
    {Res, Req, State};

read(Req, State = #state{path = [?UUID(_Org)], obj = OrgObj}) ->
    {to_json(OrgObj), Req, State};

read(Req, State = #state{path = [?UUID(Org), <<"accounting">>]}) ->
    {QS, Req1} = cowboy_req:qs_vals(Req),
    case lists:sort(QS) of
        [{<<"end">>, End}, {<<"start">>, Start}] when Start < End ->
            {ok, Data} = ls_acc:get(Org, Start, End),
            {[acc_to_js(E) || E <- Data], Req1, State};
        _ ->
            {false, Req1, State}
    end;

read(Req, State = #state{version = ?V1, path = [?UUID(_Org), <<"triggers">>],
                         obj = OrgObj}) ->
    {jsxd:get(<<"triggers">>, [], to_json(OrgObj)), Req, State}.

acc_to_js({Timestamp, Action, Resource, Metadata}) ->
    [
     {<<"action">>, atom_to_binary(utf8, Action)},
     {<<"metadata">>, Metadata},
     {<<"resource">>, Resource},
     {<<"timestamp">>, Timestamp}
    ].
%%--------------------------------------------------------------------
%% PUT
%%--------------------------------------------------------------------

create(Req, State = #state{path = [], version = Version}, Decoded) ->
    {ok, Org} = jsxd:get(<<"name">>, Decoded),
    Start = erlang:system_time(micro_seconds),
    {ok, UUID} = ls_org:add(Org),
    e2qc:teardown(?LIST_CACHE),
    e2qc:teardown(?FULL_CACHE),
    ?MSnarl(?P(State), Start),
    {{true, <<"/api/", Version/binary, "/orgs/", UUID/binary>>},
     Req, State#state{body = Decoded}};

create(Req, State =
           #state{
              path = [?UUID(Org), <<"triggers">>, Trigger],
              version = Version
             }, Event) ->
    P = erlangify_trigger(Trigger, Event),
    Start = erlang:system_time(micro_seconds),
    ok = ls_org:add_trigger(Org, P),
    e2qc:evict(?CACHE, Org),
    e2qc:teardown(?FULL_CACHE),
    ?MSnarl(?P(State), Start),
    {{true, <<"/api/", Version/binary, "/orgs/", Org/binary>>},
     Req, State}.

write(Req, State = #state{path = [?UUID(Org), <<"metadata">> | Path]}, [{K, V}])
  when is_binary(Org) ->
    Start = erlang:system_time(micro_seconds),
    ls_org:set_metadata(Org, [{[<<"public">> | Path] ++ [K], jsxd:from_list(V)}]),
    e2qc:evict(?CACHE, Org),
    e2qc:teardown(?FULL_CACHE),
    ?MSnarl(?P(State), Start),
    {true, Req, State}.

%%--------------------------------------------------------------------
%% DEETE
%%--------------------------------------------------------------------

delete(Req, State = #state{path = [?UUID(Org), <<"metadata">> | Path]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_org:set_metadata(Org, [{[<<"public">> | Path], delete}]),
    e2qc:evict(?CACHE, Org),
    e2qc:teardown(?FULL_CACHE),
    ?MSnarl(?P(State), Start),
    {true, Req, State};

delete(Req, State = #state{path = [?UUID(Org), <<"triggers">> , Trigger]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_org:remove_trigger(Org, Trigger),
    e2qc:evict(?CACHE, Org),
    e2qc:teardown(?FULL_CACHE),
    ?MSnarl(?P(State), Start),
    {true, Req, State};

delete(Req, State = #state{path = [?UUID(Org)]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_org:delete(Org),
    e2qc:evict(?CACHE, Org),
    e2qc:teardown(?LIST_CACHE),
    e2qc:teardown(?FULL_CACHE),
    ?MSnarl(?P(State), Start),
    {true, Req, State}.

%%--------------------------------------------------------------------
%% Internal Functions
%%--------------------------------------------------------------------

to_json(E) ->
    E1 = ft_org:to_json(E),
    jsxd:update([<<"metadata">>],
                fun(M) ->
                        jsxd:get([<<"public">>], [{}], M)
                end, [{}], E1).

erlangify_trigger(<<"user_create">>, Event) ->
    {user_create,
     erlangify_trigger(Event)};

erlangify_trigger(<<"dataset_create">>, Event) ->
    {dataset_create,
     erlangify_trigger(Event)};

erlangify_trigger(<<"vm_create">>, Event) ->
    {vm_create,
     erlangify_trigger(Event)}.

erlangify_trigger([{<<"action">>, <<"join_role">>},
                   {<<"target">>, Role}]) ->
    {join, role, Role};

erlangify_trigger([{<<"action">>, <<"join_org">>},
                   {<<"target">>, Org}]) ->
    {join, org, Org};

erlangify_trigger([{<<"action">>, <<"role_grant">>},
                   {<<"base">>, Base},
                   {<<"permission">>, Permission},
                   {<<"target">>, Target}]) ->
    {grant, role, Target,
     [Base, placeholder | Permission]};

erlangify_trigger([{<<"action">>, <<"user_grant">>},
                   {<<"base">>, Base},
                   {<<"permission">>, Permission},
                   {<<"target">>, Target}]) ->
    {grant, user, Target,
     [Base, placeholder | Permission]}.
