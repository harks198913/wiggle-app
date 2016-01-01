-module(wiggle_hypervisor_h).
-include("wiggle.hrl").

-define(CACHE, hypervisor).
-define(LIST_CACHE, hypervisor_list).
-define(FULL_CACHE, hypervisor_full_list).

-export([allowed_methods/3,
         permission_required/2,
         get/1,
         read/2,
         write/3,
         create/3,
         delete/2]).

-behaviour(wiggle_rest_h).

allowed_methods(_Version, _Token, []) ->
    [<<"GET">>];

allowed_methods(_Version, _Token, [?UUID(_Hypervisor)]) ->
    [<<"GET">>, <<"DELETE">>];

allowed_methods(?V2, _Token, [?UUID(_Hypervisor), <<"metrics">>| _]) ->
    [<<"GET">>];

allowed_methods(_Version, _Token, [?UUID(_Hypervisor), <<"config">>|_]) ->
    [<<"PUT">>];

allowed_methods(_Version, _Token,
                [?UUID(_Hypervisor), <<"characteristics">> | _]) ->
    [<<"PUT">>, <<"DELETE">>];

allowed_methods(_Version, _Token, [?UUID(_Hypervisor), <<"metadata">>|_]) ->
    [<<"PUT">>, <<"DELETE">>];


allowed_methods(_Version, _Token, [?UUID(_Hypervisor), <<"services">>]) ->
    [<<"PUT">>].

get(#state{path = [?UUID(_Hypervisor), <<"metrics">>]}) ->
    {ok, erlang:system_time(micro_seconds)};

get(State = #state{path = [?UUID(Hypervisor) | _]}) ->
    Start = erlang:system_time(micro_seconds),
    R = case application:get_env(wiggle, hypervisor_ttl) of
            {ok, {TTL1, TTL2}} ->
                wiggle_h:timeout_cache_with_invalid(
                  ?CACHE, Hypervisor, TTL1, TTL2, not_found,
                  fun() -> ls_hypervisor:get(Hypervisor) end);
            _ ->
                ls_hypervisor:get(Hypervisor)
        end,
    ?MSniffle(?P(State), Start),
    R;

get(_State) ->
    not_found.

permission_required(get, []) ->
    {ok, [<<"cloud">>, <<"hypervisors">>, <<"list">>]};

permission_required(get, [?UUID(Hypervisor)]) ->
    {ok, [<<"hypervisors">>, Hypervisor, <<"get">>]};

permission_required(get, [?UUID(Hypervisor), <<"metrics">> | _]) ->
    {ok, [<<"hypervisors">>, Hypervisor, <<"get">>]};

permission_required(delete, [?UUID(Hypervisor)]) ->
    {ok, [<<"hypervisors">>, Hypervisor, <<"edit">>]};

permission_required(put, [?UUID(Hypervisor), <<"config">> | _]) ->
    {ok, [<<"hypervisors">>, Hypervisor, <<"edit">>]};

permission_required(put, [?UUID(Hypervisor), <<"metadata">> | _]) ->
    {ok, [<<"hypervisors">>, Hypervisor, <<"edit">>]};

permission_required(delete, [?UUID(Hypervisor), <<"metadata">> | _]) ->
    {ok, [<<"hypervisors">>, Hypervisor, <<"edit">>]};

permission_required(put, [?UUID(Hypervisor), <<"characteristics">> | _]) ->
    {ok, [<<"hypervisors">>, Hypervisor, <<"edit">>]};

permission_required(delete, [?UUID(Hypervisor), <<"characteristics">> | _]) ->
    {ok, [<<"hypervisors">>, Hypervisor, <<"edit">>]};


permission_required(put, [?UUID(Hypervisor), <<"services">>]) ->
    {ok, [<<"hypervisors">>, Hypervisor, <<"edit">>]};

permission_required(_Method, _Path) ->
    undefined.

%%--------------------------------------------------------------------
%% GET
%%--------------------------------------------------------------------
read(Req, State = #state{path = []}) ->
    wiggle_h:list(<<"hypervisors">>,
                  fun ls_hypervisor:stream/3,
                  fun ft_hypervisor:uuid/1,
                  fun ft_hypervisor:to_json/1,
                  Req, State);

read(Req, State = #state{path = [?UUID(_Hypervisor), <<"services">>, Service],
                         obj = Obj}) ->
    {jsxd:get([Service], [{}], ft_hypervisor:services(Obj)), Req, State};

read(Req, State = #state{path = [?UUID(_Hypervisor)], obj = Obj}) ->
    {ft_hypervisor:to_json(Obj), Req, State};

read(Req, State = #state{path = [?UUID(Hypervisor), <<"metrics">>]}) ->
    {QS, Req1} = cowboy_req:qs_vals(Req),
    case perf(Hypervisor, QS) of
        {ok, JSON} ->
            {JSON, Req1, State};
        {error, no_results} ->
            {ok, Req2} = cowboy_req:reply(503, [], <<"Empty result set">>,
                                          Req1),
            {halt, Req2, State};
        {error, bad_qs} ->
            {ok, Req2} = cowboy_req:reply(
                           400, [], <<"bad qeruy string">>, Req1),
            {halt, Req2, State};
        {error, bad_resolution} ->
            {ok, Req2} = cowboy_req:reply(400, [], <<"bad resolution">>, Req1),
            {halt, Req2, State}
    end.

%%--------------------------------------------------------------------
%% PUT
%%--------------------------------------------------------------------

create(Req, State, _Data) ->
    {halt, Req, State}.

write(Req, State = #state{path = [?UUID(Hypervisor), <<"config">>]},
      [{<<"alias">>, V}]) when is_binary(V) ->
    Start = erlang:system_time(micro_seconds),
    e2qc:evict(?CACHE, Hypervisor),
    e2qc:teardown(?FULL_CACHE),
    ls_hypervisor:alias(Hypervisor, V),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

write(Req, State = #state{path = [?UUID(Hypervisor), <<"config">>]},
      [{<<"path">>, P}]) when is_list(P) ->
    Start = erlang:system_time(micro_seconds),
    e2qc:evict(?CACHE, Hypervisor),
    e2qc:teardown(?FULL_CACHE),
    ls_hypervisor:path(Hypervisor, path_to_erl(P)),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

write(Req, State = #state{path = [?UUID(Hypervisor), <<"characteristics">>
                                      | Path]}, [{K, V}]) ->
    Start = erlang:system_time(micro_seconds),
    e2qc:evict(?CACHE, Hypervisor),
    e2qc:teardown(?FULL_CACHE),
    ls_hypervisor:set_characteristic(
      Hypervisor, [{Path ++ [K], jsxd:from_list(V)}]),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

write(Req, State = #state{path = [?UUID(Hypervisor), <<"metadata">> | Path]},
      [{K, V}]) ->
    Start = erlang:system_time(micro_seconds),
    e2qc:evict(?CACHE, Hypervisor),
    e2qc:teardown(?FULL_CACHE),
    ls_hypervisor:set_metadata(
      Hypervisor, [{Path ++ [K], jsxd:from_list(V)}]),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

write(Req, State = #state{path = [?UUID(Hypervisor), <<"services">>]},
      [{<<"action">>, <<"enable">>},
       {<<"service">>, Service}]) ->
    e2qc:evict(?CACHE, Hypervisor),
    e2qc:teardown(?FULL_CACHE),
    ls_hypervisor:service_action(Hypervisor, enable, Service),
    {true, Req, State};

write(Req, State = #state{path = [?UUID(Hypervisor), <<"services">>]},
      [{<<"action">>, <<"disable">>},
       {<<"service">>, Service}]) ->
    e2qc:evict(?CACHE, Hypervisor),
    e2qc:teardown(?FULL_CACHE),
    ls_hypervisor:service_action(Hypervisor, disable, Service),
    {true, Req, State};

write(Req, State = #state{path = [?UUID(Hypervisor), <<"services">>]},
      [{<<"action">>, <<"clear">>},
       {<<"service">>, Service}]) ->
    e2qc:evict(?CACHE, Hypervisor),
    e2qc:teardown(?FULL_CACHE),
    ls_hypervisor:service_action(Hypervisor, clear, Service),
    {true, Req, State};

write(Req, State = #state{path = [?UUID(Hypervisor), <<"services">>]},
      [{<<"action">>, <<"refresh">>},
       {<<"service">>, Service}]) ->
    e2qc:evict(?CACHE, Hypervisor),
    e2qc:teardown(?FULL_CACHE),
    ls_hypervisor:service_action(Hypervisor, refresh, Service),
    {true, Req, State};

write(Req, State = #state{path = [?UUID(Hypervisor), <<"services">>]},
      [{<<"action">>, <<"restart">>},
       {<<"service">>, Service}]) ->
    e2qc:evict(?CACHE, Hypervisor),
    e2qc:teardown(?FULL_CACHE),
    ls_hypervisor:service_action(Hypervisor, restart, Service),
    {true, Req, State};

write(Req, State, _Body) ->
    {false, Req, State}.

%%--------------------------------------------------------------------
%% DELETE
%%--------------------------------------------------------------------

delete(Req, State = #state{path = [?UUID(Hypervisor)]}) ->
    Start = erlang:system_time(micro_seconds),
    e2qc:evict(?CACHE, Hypervisor),
    e2qc:teardown(?FULL_CACHE),
    e2qc:teardown(?LIST_CACHE),
    ls_hypervisor:unregister(Hypervisor),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

delete(Req, State = #state{path = [?UUID(Hypervisor), <<"characteristics">>
                                       | Path]}) ->
    Start = erlang:system_time(micro_seconds),
    e2qc:evict(?CACHE, Hypervisor),
    e2qc:teardown(?FULL_CACHE),
    ls_hypervisor:set_characteristic(Hypervisor, [{Path, delete}]),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

delete(Req,
       State = #state{path = [?UUID(Hypervisor), <<"metadata">> | Path]}) ->
    Start = erlang:system_time(micro_seconds),
    e2qc:evict(?CACHE, Hypervisor),
    e2qc:teardown(?FULL_CACHE),
    ls_hypervisor:set_metadata(Hypervisor, [{Path, delete}]),
    ?MSniffle(?P(State), Start),
    {true, Req, State}.

%%--------------------------------------------------------------------
%% Internal
%%--------------------------------------------------------------------
path_to_erl(P) ->
    [{N, C} || [{<<"cost">>, C}, {<<"name">>, N}] <- P,
               is_integer(C), is_binary(N), N /= <<>>].


perf(Hv, QS) ->
    Elems = perf_cpu(Hv),
    wiggle_metrics:get(Elems, QS).

perf_cpu(Hv) ->
    [{"cpu-kernel",  cpu(Hv, kernel)},
     {"cpu-idle",    cpu(Hv, idle)},
     {"cpu-user",    cpu(Hv, user)}].

h(L) ->
    {m, server, L}.

cpu(Hv, Metric) ->
    {f, derivate, [{f, sum, [h([Hv, cpu, "*", Metric])]}]}.
