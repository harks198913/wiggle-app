%% Feel free to use, reuse and abuse the code in this file.

%% @doc Hello world handler.
-module(wiggle_grouping_h).
-include("wiggle.hrl").

-define(CACHE, grouping).
-define(LIST_CACHE, grouping_list).
-define(FULL_CACHE, grouping_full_list).

-export([allowed_methods/3,
         get/1,
         permission_required/2,
         read/2,
         create/3,
         write/3,
         delete/2]).

-behaviour(wiggle_rest_h).

allowed_methods(_Version, _Token, [?UUID(_Grouping), <<"metadata">>|_]) ->
    [<<"PUT">>, <<"DELETE">>];

allowed_methods(_Version, _Token, [?UUID(_Grouping), <<"config">>|_]) ->
    [<<"PUT">>, <<"DELETE">>];

allowed_methods(_Version, _Token, [?UUID(_Grouping), <<"elements">>, _]) ->
    [<<"PUT">>, <<"DELETE">>];

allowed_methods(_Version, _Token, [?UUID(_Grouping), <<"groupings">>, _]) ->
    [<<"PUT">>, <<"DELETE">>];

allowed_methods(_Version, _Token, []) ->
    [<<"GET">>, <<"POST">>];

allowed_methods(_Version, _Token, [?UUID(_Grouping)]) ->
    [<<"GET">>, <<"PUT">>, <<"DELETE">>].

get(State = #state{path = [?UUID(Grouping) | _]}) ->
    Start = erlang:system_time(micro_seconds),
    R = case application:get_env(wiggle, grouping_ttl) of
            {ok, {TTL1, TTL2}} ->
                wiggle_h:timeout_cache_with_invalid(
                  ?CACHE, Grouping, TTL1, TTL2, not_found,
                  fun() -> ls_grouping:get(Grouping) end);
            _ ->
                ls_grouping:get(Grouping)
        end,
    ?MSniffle(?P(State), Start),
    R;

get(_State) ->
    not_found.

permission_required(get, []) ->
    {ok, [<<"cloud">>, <<"groupings">>, <<"list">>]};

permission_required(post, []) ->
    {ok, [<<"cloud">>, <<"groupings">>, <<"create">>]};

permission_required(get, [?UUID(Grouping)]) ->
    {ok, [<<"groupings">>, Grouping, <<"get">>]};

permission_required(delete, [?UUID(Grouping)]) ->
    {ok, [<<"groupings">>, Grouping, <<"delete">>]};

permission_required(put, [?UUID(_Grouping)]) ->
    {ok, [<<"cloud">>, <<"groupings">>, <<"create">>]};

permission_required(put, [?UUID(Grouping), <<"elements">>,  _]) ->
    {ok, [<<"groupings">>, Grouping, <<"edit">>]};

permission_required(delete, [?UUID(Grouping), <<"elements">>, _]) ->
    {ok, [<<"groupings">>, Grouping, <<"edit">>]};

permission_required(put, [?UUID(Grouping), <<"groupings">>,  _]) ->
    {ok, [<<"groupings">>, Grouping, <<"edit">>]};

permission_required(delete, [?UUID(Grouping), <<"groupings">>, _]) ->
    {ok, [<<"groupings">>, Grouping, <<"edit">>]};

permission_required(put, [?UUID(Grouping), <<"metadata">> | _]) ->
    {ok, [<<"groupings">>, Grouping, <<"edit">>]};

permission_required(delete, [?UUID(Grouping), <<"metadata">> | _]) ->
    {ok, [<<"groupings">>, Grouping, <<"edit">>]};

permission_required(pot, [?UUID(Grouping), <<"config">> | _]) ->
    {ok, [<<"groupings">>, Grouping, <<"edit">>]};

permission_required(delete, [?UUID(Grouping), <<"config">> | _]) ->
    {ok, [<<"groupings">>, Grouping, <<"edit">>]};

permission_required(_Method, _Path) ->
    undefined.

%%--------------------------------------------------------------------
%% GET
%%--------------------------------------------------------------------

join_elements(Filter, Gs) ->
    << <<",", (jsx:encode(jsxd:select(Filter, ft_grouping:to_json(G))))/binary>>
      || {_, G} <- Gs>>.

stream_elements(Send, Filter, Permission) ->
    FoldFn =
        fun({data, [{_, H} | T]}, first) ->
                H1 = jsx:encode(jsxd:select(Filter, ft_grouping:to_json(H))),
                Send(<<"[", H1/binary, (join_elements(Filter, T))/binary>>),
                ok;
           ({data, Gs}, _) ->
                Send(join_elements(Filter, Gs)),
                ok;
           (done, _) ->
                Send(<<"]">>),
                ok
        end,
    ls_grouping:stream(Permission, FoldFn, []),
    ok.

read(Req, State = #state{token = Token, path = [], full_list=true,
                         full_list_fields=Filter, encoding = json}) ->
    {ok, Permissions} = wiggle_h:get_permissions(Token),
    Permission = [{must, 'allowed',
                   [<<"groupings">>, {<<"res">>, <<"uuid">>}, <<"get">>],
                   Permissions}],
    StreamFn =
        fun(SendChunk) ->
                stream_elements(SendChunk, Filter, Permission)
        end,
    {{chunked, StreamFn}, Req, State};

read(Req, State = #state{token = Token, path = [], full_list=true,
                         full_list_fields=Filter}) ->
    Start = erlang:system_time(micro_seconds),
    {ok, Permissions} = wiggle_h:get_permissions(Token),
    ?MSnarl(?P(State), Start),
    Start1 = erlang:system_time(micro_seconds),
    Permission = [{must, 'allowed',
                   [<<"groupings">>, {<<"res">>, <<"uuid">>}, <<"get">>],
                   Permissions}],
    FoldFn = fun({data, Groupings}, Acc) ->
                     [jsxd:select(Filter, ft_grouping:to_json(G)) ||
                         {_, G} <- Groupings] ++ Acc;
                (done, Acc) ->
                     {ok, Acc}
             end,
    {ok, Res} = ls_grouping:stream(Permission, FoldFn, []),
    %% Res = wiggle_h:list(fun ls_grouping:list/2,
    %%                     fun ft_grouping:to_json/1, Token, Permission,
    %%                     FullList, Filter, grouping_list_ttl, ?FULL_CACHE,
    %%                     ?LIST_CACHE),
    ?MSniffle(?P(State), Start1),
    {Res, Req, State};

read(Req, State = #state{token = Token, path = [], full_list=false}) ->
    Start = erlang:system_time(micro_seconds),
    {ok, Permissions} = wiggle_h:get_permissions(Token),
    ?MSnarl(?P(State), Start),
    Start1 = erlang:system_time(micro_seconds),
    Permission = [{must, 'allowed',
                   [<<"groupings">>, {<<"res">>, <<"uuid">>}, <<"get">>],
                   Permissions}],
    FoldFn = fun({data, Groupings}, Acc) ->
                     [ft_grouping:uuid(G) ||
                         {_, G} <- Groupings] ++ Acc;
                (done, Acc) ->
                     {ok, Acc}
             end,
    {ok, Res} = ls_grouping:stream(Permission, FoldFn, []),
    ?MSniffle(?P(State), Start1),
    {Res, Req, State};

read(Req, State = #state{path = [?UUID(_Grouping)], obj = Obj}) ->
    {ft_grouping:to_json(Obj), Req, State}.

%%--------------------------------------------------------------------
%% PUT
%%--------------------------------------------------------------------

create(Req, State = #state{path = [], version = Version, token=Token},
       [{<<"name">>, Name}, {<<"type">>, TypeS}] = Data) ->
    Type = case TypeS of
               <<"cluster">> ->
                   cluster;
               <<"stack">> ->
                   stack;
               _ ->
                   none
           end,
    Start = erlang:system_time(micro_seconds),
    case ls_grouping:add(Name, Type) of
        {ok, UUID} ->
            e2qc:teardown(?LIST_CACHE),
            e2qc:teardown(?FULL_CACHE),
            {ok, User} = ls_user:get(Token),
            case ft_user:active_org(User) of
                <<Org:36/binary>> ->
                    ls_org:execute_trigger(Org, grouping_create, UUID);
                _ ->
                    ok
            end,
            ?MSniffle(?P(State), Start),
            {{true, <<"/api/", Version/binary, "/groupings/", UUID/binary>>},
             Req, State#state{body = Data}};
        duplicate ->
            ?MSniffle(?P(State), Start),
            {ok, Req1} = cowboy_req:reply(409, Req),
            {halt, Req1, State}
    end.

write(Req, State = #state{path = [?UUID(Grouping), <<"elements">>, Element]},
      _Data) ->
    Start = erlang:system_time(micro_seconds),
    case ls_grouping:add_element(Grouping, Element) of
        ok ->
            e2qc:evict(?CACHE, Grouping),
            e2qc:teardown(?FULL_CACHE),
            ?MSniffle(?P(State), Start),
            {true, Req, State};
        _ ->
            ?MSniffle(?P(State), Start),
            {false, Req, State}
    end;

write(Req, State = #state{path = [?UUID(Grouping), <<"groupings">>, Element]},
      _Data) ->
    Start = erlang:system_time(micro_seconds),
    case ls_grouping:add_grouping(Grouping, Element) of
        ok ->
            e2qc:evict(?CACHE, Grouping),
            e2qc:teardown(?FULL_CACHE),
            ?MSniffle(?P(State), Start),
            {true, Req, State};
        _ ->
            ?MSniffle(?P(State), Start),
            {false, Req, State}
    end;

write(Req, State = #state{method = <<"POST">>, path = []}, _) ->
    {true, Req, State};

write(Req, State = #state{path = [?UUID(Grouping), <<"metadata">> | Path]},
      [{K, V}]) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_grouping:set_metadata(Grouping, [{Path ++ [K], jsxd:from_list(V)}]),
    e2qc:evict(?CACHE, Grouping),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

write(Req, State = #state{path = [?UUID(Grouping), <<"config">> | Path]},
      [{K, V}]) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_grouping:set_config(Grouping, [{Path ++ [K], jsxd:from_list(V)}]),
    e2qc:evict(?CACHE, Grouping),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

write(Req, State, _Body) ->
    {false, Req, State}.

%%--------------------------------------------------------------------
%% DEETE
%%--------------------------------------------------------------------

delete(Req, State = #state{path = [?UUID(Grouping), <<"metadata">> | Path]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_grouping:set_metadata(Grouping, [{Path, delete}]),
    e2qc:evict(?CACHE, Grouping),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

delete(Req, State = #state{path = [?UUID(Grouping), <<"config">> | Path]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_grouping:set_config(Grouping, [{Path, delete}]),
    e2qc:evict(?CACHE, Grouping),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

delete(Req,
       State = #state{path = [?UUID(Grouping), <<"elements">>, Element]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_grouping:remove_element(Grouping, Element),
    e2qc:evict(?CACHE, Grouping),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

delete(Req,
       State = #state{path = [?UUID(Grouping), <<"groupings">>, Element]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_grouping:remove_grouping(Grouping, Element),
    e2qc:evict(?CACHE, Grouping),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

delete(Req, State = #state{path = [?UUID(Grouping)]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_grouping:delete(Grouping),
    e2qc:evict(?CACHE, Grouping),
    e2qc:teardown(?LIST_CACHE),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {true, Req, State}.
