%% Feel free to use, reuse and abuse the code in this file.

%% @doc Hello world handler.
-module(wiggle_network_h).
-include("wiggle.hrl").

-define(CACHE, network).
-define(LIST_CACHE, network_list).
-define(FULL_CACHE, network_full_list).

-export([allowed_methods/3,
         get/1,
         permission_required/2,
         read/2,
         create/3,
         write/3,
         delete/2]).

-behaviour(wiggle_rest_h).

allowed_methods(_Version, _Token, [?UUID(_Network), <<"metadata">>|_]) ->
    [<<"PUT">>, <<"DELETE">>];

allowed_methods(_Version, _Token, [?UUID(_Network), <<"ipranges">>, _]) ->
    [<<"PUT">>, <<"DELETE">>];

allowed_methods(_Version, _Token, []) ->
    [<<"GET">>, <<"POST">>];

allowed_methods(_Version, _Token, [?UUID(_Network)]) ->
    [<<"GET">>, <<"PUT">>, <<"DELETE">>].

get(State = #state{path = [?UUID(Network) | _]}) ->
    Start = erlang:system_time(micro_seconds),
    R = case application:get_env(wiggle, network_ttl) of
            {ok, {TTL1, TTL2}} ->
                wiggle_h:timeout_cache_with_invalid(
                  ?CACHE, Network, TTL1, TTL2, not_found,
                  fun() -> ls_network:get(Network) end);
            _ ->
                ls_network:get(Network)
        end,
    ?MSniffle(?P(State), Start),
    R;

get(_State) ->
    not_found.

permission_required(get, []) ->
    {ok, [<<"cloud">>, <<"networks">>, <<"list">>]};

permission_required(post, []) ->
    {ok, [<<"cloud">>, <<"networks">>, <<"create">>]};

permission_required(get, [?UUID(Network)]) ->
    {ok, [<<"networks">>, Network, <<"get">>]};

permission_required(delete, [?UUID(Network)]) ->
    {ok, [<<"networks">>, Network, <<"delete">>]};

permission_required(put, [?UUID(_Network)]) ->
    {ok, [<<"cloud">>, <<"networks">>, <<"create">>]};

permission_required(put, [?UUID(Network), <<"ipranges">>,  _]) ->
    {ok, [<<"networks">>, Network, <<"edit">>]};

permission_required(delete, [?UUID(Network), <<"ipranges">>, _]) ->
    {ok, [<<"networks">>, Network, <<"edit">>]};

permission_required(put, [?UUID(Network), <<"metadata">> | _]) ->
    {ok, [<<"networks">>, Network, <<"edit">>]};

permission_required(delete, [?UUID(Network), <<"metadata">> | _]) ->
    {ok, [<<"networks">>, Network, <<"edit">>]};

permission_required(_Method, _Path) ->
    undefined.

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
                   [<<"networks">>, {<<"res">>, <<"uuid">>}, <<"get">>],
                   Permissions}],
    Res = wiggle_h:list(fun ls_network:list/2,
                        fun ft_network:to_json/1, Token, Permission,
                        FullList, Filter, network_list_ttl, ?FULL_CACHE,
                        ?LIST_CACHE),
    ?MSniffle(?P(State), Start1),
    {Res, Req, State};

read(Req, State = #state{path = [?UUID(_Network)], obj = Obj}) ->
    {ft_network:to_json(Obj), Req, State}.

%%--------------------------------------------------------------------
%% PUT
%%--------------------------------------------------------------------

create(Req, State = #state{path = [], version = Version}, Data) ->
    {ok, Network} = jsxd:get(<<"name">>, Data),
    Start = erlang:system_time(micro_seconds),
    case ls_network:create(Network) of
        {ok, UUID} ->
            ?MSniffle(?P(State), Start),
            e2qc:teardown(?LIST_CACHE),
            e2qc:teardown(?FULL_CACHE),
            {{true, <<"/api/", Version/binary, "/networks/", UUID/binary>>},
             Req, State#state{body = Data}};
        duplicate ->
            ?MSniffle(?P(State), Start),
            {ok, Req1} = cowboy_req:reply(409, Req),
            {halt, Req1, State}
    end.

write(Req, State = #state{path = [?UUID(Network), <<"ipranges">>, IPrange]},
      _Data) ->
    Start = erlang:system_time(micro_seconds),
    case ls_network:add_iprange(Network, IPrange) of
        ok ->
            ?MSniffle(?P(State), Start),
            e2qc:evict(?CACHE, Network),
            e2qc:teardown(?FULL_CACHE),
            {true, Req, State};
        _ ->
            ?MSniffle(?P(State), Start),
            {false, Req, State}
    end;

write(Req, State = #state{method = <<"POST">>, path = []}, _) ->
    {true, Req, State};

write(Req, State = #state{path = [?UUID(Network), <<"metadata">> | Path]},
      [{K, V}]) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_network:set_metadata(Network, [{Path ++ [K], jsxd:from_list(V)}]),
    e2qc:evict(?CACHE, Network),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

write(Req, State, _Body) ->
    {false, Req, State}.

%%--------------------------------------------------------------------
%% DEETE
%%--------------------------------------------------------------------

delete(Req, State = #state{path = [?UUID(Network), <<"metadata">> | Path]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_network:set_metadata(Network, [{Path, delete}]),
    e2qc:evict(?CACHE, Network),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

delete(Req, State = #state{path = [?UUID(Network), <<"ipranges">>, IPRange]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_network:remove_iprange(Network, IPRange),
    e2qc:evict(?CACHE, Network),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

delete(Req, State = #state{path = [?UUID(Network)]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_network:delete(Network),
    e2qc:evict(?CACHE, Network),
    e2qc:teardown(?LIST_CACHE),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {true, Req, State}.
