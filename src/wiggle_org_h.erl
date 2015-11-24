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
         permission_required/3,
         read/2,
         create/3,
         write/3,
         delete/2,
         schema/1]).

-behaviour(wiggle_rest_h).

allowed_methods(_Version, _Token, []) ->
    [<<"GET">>, <<"POST">>];

allowed_methods(_Version, _Token, [?UUID(_Org)]) ->
    [<<"GET">>, <<"PUT">>, <<"DELETE">>];

allowed_methods(?V2, _Token, [?UUID(_Org), <<"accounting">>]) ->
    [<<"GET">>];

allowed_methods(_Version, _Token, [?UUID(_Org), <<"triggers">> | _Trigger]) ->
    [<<"POST">>, <<"DELETE">>];

allowed_methods(_Version, _Token, [?UUID(_Org), <<"metadata">> | _]) ->
    [<<"PUT">>, <<"DELETE">>];

allowed_methods(_Version, _Token, [?UUID(_Org), <<"resources">>, _]) ->
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

permission_required(get, [], _) ->
    {ok, [<<"cloud">>, <<"orgs">>, <<"list">>]};

permission_required(post, [], _) ->
    {ok, [<<"cloud">>, <<"orgs">>, <<"create">>]};

permission_required(get, [?UUID(Org)], _) ->
    {ok, [<<"orgs">>, Org, <<"get">>]};

permission_required(get, [?UUID(Org), <<"accounting">>], _) ->
    {ok, [<<"orgs">>, Org, <<"get">>]};

permission_required(put, [?UUID(Org)], _) ->
    {ok, [<<"orgs">>, Org, <<"create">>]};

permission_required(delete, [?UUID(Org)], _) ->
    {ok, [<<"orgs">>, Org, <<"delete">>]};

permission_required(post, [?UUID(_Org), <<"triggers">> | _],
                    #state{body = undefined}) ->
    {error, needs_decode};

permission_required(post, [?UUID(Org), <<"triggers">> | _],
                    #state{body = [{<<"action">>, <<"role_grant">>},
                                   {<<"base">>, _},
                                   {<<"permission">>, _},
                                   {<<"target">>, Role}]}) ->
    {multiple, [[<<"orgs">>, Org, <<"edit">>],
                [<<"roles">>, Role, <<"grant">>]]};

permission_required(post, [?UUID(Org), <<"triggers">> | _],
                    #state{body = [{<<"action">>, <<"user_grant">>},
                                   {<<"base">>, _Base},
                                   {<<"permission">>, _Permission},
                                   {<<"target">>, User}]}) ->
    {multiple, [[<<"orgs">>, Org, <<"edit">>],
                [<<"users">>, User, <<"grant">>]]};

permission_required(post, [?UUID(Org), <<"triggers">> | _],
                    #state{body = [{<<"action">>, <<"join_role">>},
                                   {<<"target">>, Role}]}) ->
    {multiple, [[<<"orgs">>, Org, <<"edit">>],
                [<<"roles">>, Role, <<"join">>]]};

permission_required(post, [?UUID(Org), <<"triggers">> | _],
                    #state{body = ([{<<"action">>, <<"join_org">>},
                                    {<<"target">>, TargetOrg}])}) ->
    {multiple, [[<<"orgs">>, Org, <<"edit">>],
                [<<"orgs">>, TargetOrg, <<"join">>]]};

permission_required(delete, [?UUID(Org), <<"triggers">> | _], _) ->
    {ok, [<<"orgs">>, Org, <<"edit">>]};

permission_required(put, [?UUID(Org), <<"metadata">> | _], _) ->
    {ok, [<<"orgs">>, Org, <<"edit">>]};

permission_required(delete, [?UUID(Org), <<"metadata">> | _], _) ->
    {ok, [<<"orgs">>, Org, <<"edit">>]};

permission_required(put, [?UUID(Org), <<"resources">>, _], _) ->
    {ok, [<<"orgs">>, Org, <<"edit">>]};

permission_required(delete, [?UUID(Org), <<"resources">>, _], _) ->
    {ok, [<<"orgs">>, Org, <<"edit">>]};

permission_required(_Method, _Path, _State) ->
    undefined.

%%--------------------------------------------------------------------
%% Schema
%%--------------------------------------------------------------------

%% Change resources
schema(#state{method = <<"PUT">>, path = [?UUID(_Org), <<"resources">>, _]}) ->
    org_resource_change;

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
        [{<<"end">>, EndB}, {<<"start">>, StartB}] ->
            Start = binary_to_integer(StartB),
            End = binary_to_integer(EndB),
            {ok, Data} = ls_acc:get(Org, Start, End),
            {[acc_to_js(E) || E <- Data], Req1, State};
        _ ->
            {false, Req1, State}
    end.

acc_to_js({Timestamp, Action, Resource, Metadata}) ->
    [
     {<<"action">>, atom_to_binary(Action, utf8)},
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
    ls_org:set_metadata(Org, [{[<<"public">> | Path] ++ [K],
                               jsxd:from_list(V)}]),
    e2qc:evict(?CACHE, Org),
    e2qc:teardown(?FULL_CACHE),
    ?MSnarl(?P(State), Start),
    {true, Req, State};

write(Req, State = #state{path = [?UUID(Org), <<"resources">>, R]},
      [{Act, V}])
  when is_integer(V),
       (Act =:= <<"inc">> orelse Act =:= <<"dec">>) ->
    Start = erlang:system_time(micro_seconds),
    case Act of
        <<"inc">> ->
            ls_org:resource_inc(Org, R, V);
        <<"dec">> ->
            ls_org:resource_dec(Org, R, V)
    end,
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
