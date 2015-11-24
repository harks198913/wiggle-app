%% Feel free to use, reuse and abuse the code in this file.

%% @doc Hello world handler.
-module(wiggle_iprange_h).
-include("wiggle.hrl").

-define(CACHE, iprange).
-define(LIST_CACHE, iprange_list).
-define(FULL_CACHE, iprange_full_list).

-export([allowed_methods/3,
         get/1,
         permission_required/2,
         read/2,
         create/3,
         write/3,
         delete/2]).

-behaviour(wiggle_rest_h).

allowed_methods(_Version, _Token, [?UUID(_Iprange), <<"metadata">>|_]) ->
    [<<"PUT">>, <<"DELETE">>];

allowed_methods(_Version, _Token, []) ->
    [<<"GET">>, <<"POST">>];

allowed_methods(_Version, _Token, [?UUID(_Iprange)]) ->
    [<<"GET">>, <<"PUT">>, <<"DELETE">>];

allowed_methods(_Version, _Token, [?UUID(_Iprange), _IP]) ->
    [<<"DELETE">>].

get(State = #state{path = [?UUID(Iprange) | _]}) ->
    Start = erlang:system_time(micro_seconds),
    R = case application:get_env(wiggle, iprange_ttl) of
            {ok, {TTL1, TTL2}} ->
                wiggle_h:timeout_cache_with_invalid(
                  ?CACHE, Iprange, TTL1, TTL2, not_found,
                  fun() -> ls_iprange:get(Iprange) end);
            _ ->
                ls_iprange:get(Iprange)
        end,
    ?MSniffle(?P(State), Start),
    R;

get(_State) ->
    not_found.

permission_required(get, []) ->
    {ok, [<<"cloud">>, <<"ipranges">>, <<"list">>]};

permission_required(post, []) ->
    {ok, [<<"cloud">>, <<"ipranges">>, <<"create">>]};

permission_required(get, [?UUID(Iprange)]) ->
    {ok, [<<"ipranges">>, Iprange, <<"get">>]};

permission_required(delete, [?UUID(Iprange)]) ->
    {ok, [<<"ipranges">>, Iprange, <<"delete">>]};

permission_required(put, [?UUID(Iprange)]) ->
    {ok, [<<"ipranges">>, Iprange, <<"edit">>]};

permission_required(delete, [?UUID(Iprange), _IP]) ->
    {ok, [<<"ipranges">>, Iprange, <<"edit">>]};

permission_required(put, [?UUID(Iprange), <<"metadata">> | _]) ->
    {ok, [<<"ipranges">>, Iprange, <<"edit">>]};

permission_required(delete, [?UUID(Iprange), <<"metadata">> | _]) ->
    {ok, [<<"ipranges">>, Iprange, <<"edit">>]};

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
                   [<<"ipranges">>, {<<"res">>, <<"uuid">>}, <<"get">>],
                   Permissions}],
    %% We can't use the wiggle_h:list_fn/4 since we need to
    %% apply a transformation to the objects when full list is given.
    Fun = fun() ->
                  {ok, Res} = ls_iprange:list(Permission, FullList),
                  case {Filter, FullList} of
                      {_, false} ->
                          [ID || {_, ID} <- Res];
                      {[], _} ->
                          [to_json(Obj) || {_, Obj} <- Res];
                      _ ->
                          [jsxd:select(Filter, to_json(Obj)) || {_, Obj} <- Res]
                  end
          end,
    Res1 = case application:get_env(wiggle, iprange_list_ttl) of
               {ok, {TTL1, TTL2}} ->
                   case FullList of
                       true ->
                           wiggle_h:timeout_cache(
                             ?FULL_CACHE, {Token, Filter}, TTL1, TTL2, Fun);
                       _ ->
                           wiggle_h:timeout_cache(
                             ?LIST_CACHE, Token, TTL1, TTL2, Fun)
                   end;
               _ ->
                   Fun()
           end,
    ?MSnarl(?P(State), Start1),
    {Res1, Req, State};

read(Req, State = #state{path = [?UUID(_Iprange)], obj = Obj}) ->
    {to_json(Obj), Req, State}.

to_json(Obj) ->
    jsxd:thread([{update, <<"network">>, fun ls_iprange:ip_to_bin/1},
                 {update, <<"gateway">>, fun ls_iprange:ip_to_bin/1},
                 {update, <<"netmask">>, fun ls_iprange:ip_to_bin/1},
                 {update, <<"free">>,
                  fun (Free) ->
                          lists:map(fun ls_iprange:ip_to_bin/1, Free)
                  end},
                 {update, <<"used">>,
                  fun (Free) ->
                          lists:map(fun ls_iprange:ip_to_bin/1, Free)
                  end}], ft_iprange:to_json(Obj)).
%%--------------------------------------------------------------------
%% POST
%%--------------------------------------------------------------------

create(Req, State = #state{path = [], version = Version}, Data) ->
    {ok, Iprange} = jsxd:get(<<"name">>, Data),
    {ok, Network} = jsxd:get(<<"network">>, Data),
    {ok, Gateway} = jsxd:get(<<"gateway">>, Data),
    {ok, Netmask} = jsxd:get(<<"netmask">>, Data),
    {ok, First} = jsxd:get(<<"first">>, Data),
    {ok, Last} = jsxd:get(<<"last">>, Data),
    {ok, Tag} = jsxd:get(<<"tag">>, Data),
    Vlan = jsxd:get(<<"vlan">>, 0, Data),
    Start = erlang:system_time(micro_seconds),
    case ls_iprange:create(Iprange, Network, Gateway, Netmask, First, Last,
                           Tag, Vlan) of
        {ok, UUID} ->
            ?MSniffle(?P(State), Start),
            e2qc:teardown(?LIST_CACHE),
            e2qc:teardown(?FULL_CACHE),
            {{true, <<"/api/", Version/binary, "/ipranges/", UUID/binary>>},
             Req, State#state{body = Data}};
        duplicate ->
            ?MSniffle(?P(State), Start),
            {ok, Req1} = cowboy_req:reply(409, Req),
            {halt, Req1, State}
    end.

%%--------------------------------------------------------------------
%% PUT
%%--------------------------------------------------------------------

write(Req, State = #state{path = [?UUID(Iprange)]}, _) ->
    case ls_iprange:claim(Iprange) of
        {ok, {Tag, IP, Netmask, Gateway, VLAN}} ->
            JSON = [
                    {<<"tag">>, Tag},
                    {<<"ip">>, ls_iprange:ip_to_bin(IP)},
                    {<<"netmask">>, ls_iprange:ip_to_bin(Netmask)},
                    {<<"gateway">>, ls_iprange:ip_to_bin(Gateway)},
                    {<<"vlan">>, VLAN}
                   ],
            {Encoder, ContentType, Req2} =
                case cowboy_req:header(<<"accept">>, Req) of
                    {<<"application/json", _/binary>>, Req1} ->
                        {fun jsx:encode/1,
                         <<"application/json">>, Req1};
                    {<<"application/x-msgpack", _/binary>>, Req1} ->
                        {fun (Body) -> msgpack:pack(Body, [jsx]) end,
                         <<"application/x-msgpack">>, Req1}
                end,
            Body = Encoder(JSON),
            {ok, Req3} =
                cowboy_req:reply(
                  200, [{<<"content-type">>, ContentType}], Body, Req2),
            {halt, Req3, State};
        _ ->
            {false, Req, State}
    end;

write(Req, State = #state{path = [?UUID(Iprange), <<"metadata">> | Path]},
      [{K, V}]) ->
    Start = erlang:system_time(micro_seconds),
    e2qc:evict(?CACHE, Iprange),
    e2qc:teardown(?FULL_CACHE),
    ls_iprange:set_metadata(Iprange, [{Path ++ [K], jsxd:from_list(V)}]),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

write(Req, State, _Body) ->
    {false, Req, State}.

%%--------------------------------------------------------------------
%% DEETE
%%--------------------------------------------------------------------

delete(Req, State = #state{path = [?UUID(Iprange), <<"metadata">> | Path]}) ->
    Start = erlang:system_time(micro_seconds),
    e2qc:evict(?CACHE, Iprange),
    e2qc:teardown(?FULL_CACHE),
    ls_iprange:set_metadata(Iprange, [{Path, delete}]),
    ?MSniffle(?P(State), Start),
    {true, Req, State};


delete(Req, State = #state{path = [?UUID(Iprange), IPS]}) ->
    Start = erlang:system_time(micro_seconds),
    IP = ls_iprange:ip_to_int(IPS),
    ok = ls_iprange:release(Iprange, IP),
    e2qc:evict(?CACHE, Iprange),
    e2qc:teardown(?LIST_CACHE),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

delete(Req, State = #state{path = [?UUID(Iprange)]}) ->
    Start = erlang:system_time(micro_seconds),
    e2qc:evict(?CACHE, Iprange),
    e2qc:teardown(?LIST_CACHE),
    e2qc:teardown(?FULL_CACHE),
    ok = ls_iprange:delete(Iprange),
    ?MSniffle(?P(State), Start),
    {true, Req, State}.
