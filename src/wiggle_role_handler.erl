-module(wiggle_role_handler).
-include("wiggle.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-define(CACHE, role).
-define(LIST_CACHE, role_list).
-define(FULL_CACHE, role_full_list).

-export([allowed_methods/3,
         get/1,
         permission_required/1,
         read/2,
         create/3,
         write/3,
         delete/2]).

-behaviour(wiggle_rest_handler).

allowed_methods(_Version, _Token, []) ->
    [<<"GET">>, <<"POST">>];

allowed_methods(_Version, _Token, [?UUID(_Role)]) ->
    [<<"GET">>, <<"PUT">>, <<"DELETE">>];

allowed_methods(_Version, _Token, [?UUID(_Role), <<"permissions">>]) ->
    [<<"GET">>];

allowed_methods(_Version, _Token, [?UUID(_Role), <<"metadata">> | _]) ->
    [<<"PUT">>, <<"DELETE">>];

allowed_methods(_Version, _Token, [?UUID(_Role), <<"permissions">> | _Permission]) ->
    [<<"PUT">>, <<"DELETE">>].

get(State = #state{path = [?UUID(Role), <<"permissions">> | Permission]}) ->
    case {Permission, wiggle_role_handler:get(State#state{path = [?UUID(Role)]})} of
        {_, not_found} ->
            not_found;
        {[], {ok, Obj}} ->
            {ok, Obj};
        {P, {ok, Obj}} ->
            case lists:member(P, ft_role:permissions(Obj)) of
                true ->
                    {ok, Obj};
                _ -> not_found
            end
    end;

get(State = #state{path = [?UUID(Role) | _]}) ->
    Start = now(),
    R = case application:get_env(wiggle, role_ttl) of
            {ok, {TTL1, TTL2}} ->
                wiggle_handler:timeout_cache_with_invalid(
                  ?CACHE, Role, TTL1, TTL2, not_found,
                  fun() -> ls_role:get(Role) end);
            _ ->
                ls_role:get(Role)
        end,
    ?MSnarl(?P(State), Start),
    R.

permission_required(#state{method = <<"GET">>, path = []}) ->
    {ok, [<<"cloud">>, <<"roles">>, <<"list">>]};

permission_required(#state{method = <<"POST">>, path = []}) ->
    {ok, [<<"cloud">>, <<"roles">>, <<"create">>]};

permission_required(#state{method = <<"GET">>, path = [?UUID(Role)]}) ->
    {ok, [<<"roles">>, Role, <<"get">>]};

permission_required(#state{method = <<"PUT">>, path = [?UUID(Role)]}) ->
    {ok, [<<"roles">>, Role, <<"create">>]};

permission_required(#state{method = <<"DELETE">>, path = [?UUID(Role)]}) ->
    {ok, [<<"roles">>, Role, <<"delete">>]};

permission_required(#state{method = <<"GET">>, path = [?UUID(Role), <<"permissions">>]}) ->
    {ok, [<<"roles">>, Role, <<"get">>]};

permission_required(#state{method = <<"PUT">>, path = [?UUID(Role), <<"permissions">> | Permission]}) ->
    {multiple, [[<<"roles">>, Role, <<"grant">>],
                [<<"permissions">>, Permission, <<"grant">>]]};

permission_required(#state{method = <<"DELETE">>, path = [?UUID(Role), <<"permissions">> | Permission]}) ->
    {multiple, [[<<"roles">>, Role, <<"revoke">>],
                [<<"permissions">>, Permission, <<"revoke">>]]};

permission_required(#state{method = <<"PUT">>, path = [?UUID(Role), <<"metadata">> | _]}) ->
    {ok, [<<"roles">>, Role, <<"edit">>]};

permission_required(#state{method = <<"DELETE">>, path = [?UUID(Role), <<"metadata">> | _]}) ->
    {ok, [<<"roles">>, Role, <<"edit">>]};

permission_required(_State) ->
    undefined.

%%--------------------------------------------------------------------
%% GET
%%--------------------------------------------------------------------


read(Req, State = #state{token = Token, path = [], full_list=FullList, full_list_fields=Filter}) ->
    Start = now(),
    {ok, Permissions} = wiggle_handler:get_persmissions(Token),
    ?MSnarl(?P(State), Start),
    Start1 = now(),
    Permission = [{must, 'allowed',
                   [<<"roles">>, {<<"res">>, <<"uuid">>}, <<"get">>],
                   Permissions}],
    Res = wiggle_handler:list(fun ls_role:list/2,
                              fun to_json/1, Token, Permission,
                              FullList, Filter, role_list_ttl, ?FULL_CACHE,
                              ?LIST_CACHE),
    ?MSniffle(?P(State), Start1),
    {Res, Req, State};

read(Req, State = #state{path = [?UUID(_Role)], obj = RoleObj}) ->
    {to_json(RoleObj), Req, State};

read(Req, State = #state{path = [?UUID(_Role), <<"permissions">>], obj = RoleObj}) ->
    {ft_role:permissions(RoleObj), Req, State}.

%%--------------------------------------------------------------------
%% PUT
%%--------------------------------------------------------------------

create(Req, State = #state{path = [], version = Version}, Decoded) ->
    {ok, Role} = jsxd:get(<<"name">>, Decoded),
    Start = now(),
    {ok, UUID} = ls_role:add(Role),
    e2qc:teardown(?LIST_CACHE),
    ?MSnarl(?P(State), Start),
    {{true, <<"/api/", Version/binary, "/roles/", UUID/binary>>}, Req, State#state{body = Decoded}}.

%% TODO : This is a icky case it is called after post.
write(Req, State = #state{method = <<"POST">>, path = []}, _) ->
    {true, Req, State};

write(Req, State = #state{path = [?UUID(Role), <<"metadata">> | Path]}, [{K, V}]) when is_binary(Role) ->
    Start = now(),
    e2qc:evict(?CACHE, Role),
    e2qc:teardown(?LIST_CACHE),
    ls_role:set_metadata(Role, [{[<<"public">> | Path] ++ [K], jsxd:from_list(V)}]),
    ?MSnarl(?P(State), Start),
    {true, Req, State};

write(Req, State = #state{path = [?UUID(Role), <<"permissions">> | Permission]}, _Body) ->
    Start = now(),
    e2qc:evict(?CACHE, Role),
    e2qc:teardown(?LIST_CACHE),
    ok = ls_role:grant(Role, Permission),
    ?MSnarl(?P(State), Start),
    {true, Req, State}.

%%--------------------------------------------------------------------
%% DEETE
%%--------------------------------------------------------------------

delete(Req, State = #state{path = [?UUID(Role), <<"metadata">> | Path]}) ->
    Start = now(),
    e2qc:evict(?CACHE, Role),
    e2qc:teardown(?LIST_CACHE),
    ls_role:set_metadata(Role, [{[<<"public">> | Path], delete}]),
    ?MSnarl(?P(State), Start),
    {true, Req, State};

delete(Req, State = #state{path = [?UUID(Role), <<"permissions">> | Permission]}) ->
    Start = now(),
    e2qc:evict(?CACHE, Role),
    e2qc:teardown(?LIST_CACHE),
    ok = ls_role:revoke(Role, Permission),
    ?MSnarl(?P(State), Start),
    {true, Req, State};

delete(Req, State = #state{path = [?UUID(Role)]}) ->
    Start = now(),
    e2qc:evict(?CACHE, Role),
    e2qc:teardown(?LIST_CACHE),
    ok = ls_role:delete(Role),
    ?MSnarl(?P(State), Start),
    {true, Req, State}.

%%--------------------------------------------------------------------
%% Internal Functions
%%--------------------------------------------------------------------

to_json(E) ->
    E1 = ft_role:to_json(E),
    jsxd:update([<<"metadata">>],
                fun(M) ->
                        jsxd:get([<<"public">>], [{}], M)
                end, [{}], E1).
