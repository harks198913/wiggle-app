%% Feel free to use, reuse and abuse the code in this file.

%% @doc Hello world handler.
-module(wiggle_package_h).
-include("wiggle.hrl").

-define(CACHE, package).
-define(LIST_CACHE, package_list).
-define(FULL_CACHE, package_full_list).

-export([allowed_methods/3,
         get/1,
         permission_required/2,
         read/2,
         create/3,
         write/3,
         delete/2,
         schema/1]).

-behaviour(wiggle_rest_h).

allowed_methods(_Version, _Token, []) ->
    [<<"GET">>, <<"POST">>];

allowed_methods(_Version, _Token, [?UUID(_Package), <<"metadata">>|_]) ->
    [<<"PUT">>, <<"DELETE">>];

allowed_methods(_Version, _Token, [?UUID(_Package)]) ->
    [<<"GET">>, <<"PUT">>, <<"DELETE">>].

get(State = #state{path = [?UUID(Package) | _]}) ->
    Start = erlang:system_time(micro_seconds),
    R = case application:get_env(wiggle, package_ttl) of
            {ok, {TTL1, TTL2}} ->
                wiggle_h:timeout_cache_with_invalid(
                  ?CACHE, Package, TTL1, TTL2, not_found,
                  fun() -> ls_package:get(Package) end);
            _ ->
                ls_package:get(Package)
        end,
    ?MSniffle(?P(State), Start),
    R;

get(_) ->
    not_found.

permission_required(get, []) ->
    {ok, [<<"cloud">>, <<"packages">>, <<"list">>]};

permission_required(post, []) ->
    {ok, [<<"cloud">>, <<"packages">>, <<"create">>]};

permission_required(get, [?UUID(Package)]) ->
    {ok, [<<"packages">>, Package, <<"get">>]};

permission_required(delete, [?UUID(Package)]) ->
    {ok, [<<"packages">>, Package, <<"delete">>]};

permission_required(put, [?UUID(_Package)]) ->
    {ok, [<<"cloud">>, <<"packages">>, <<"create">>]};

permission_required(put, [?UUID(Package), <<"metadata">> | _]) ->
    {ok, [<<"packages">>, Package, <<"edit">>]};

permission_required(delete, [?UUID(Package), <<"metadata">> | _]) ->
    {ok, [<<"packages">>, Package, <<"edit">>]};

permission_required(_Method, _Path) ->
    undefined.

%%--------------------------------------------------------------------
%% Schema
%%--------------------------------------------------------------------

%% Creates a VM
schema(#state{method = <<"PUT">>, path = []}) ->
    package_create;

schema(_State) ->
    none.

%%--------------------------------------------------------------------
%% GET
%%--------------------------------------------------------------------

read(Req, State = #state{path = []}) ->
    wiggle_h:list(<<"packages">>,
                  fun ls_package:stream/3,
                  fun ft_package:uuid/1,
                  fun ft_package:to_json/1,
                  Req, State);

read(Req, State = #state{path = [?UUID(_Package)], obj = Obj}) ->
    {ft_package:to_json(Obj), Req, State}.


%%--------------------------------------------------------------------
%% PUT
%%--------------------------------------------------------------------

create(Req, State = #state{path = [], version = Version}, Data) ->
    {ok, Package} = jsxd:get(<<"name">>, Data),
    case ls_package:create(Package) of
        {ok, UUID} ->
            do_set(
              [{<<"cpu_cap">>, fun ls_package:cpu_cap/2},
               {<<"quota">>, fun ls_package:quota/2},
               {<<"ram">>, fun ls_package:ram/2},
               {<<"zfs_io_priority">>, fun ls_package:zfs_io_priority/2},
               {<<"max_swap">>, fun ls_package:max_swap/2},
               {<<"blocksize">>, fun ls_package:blocksize/2},
               {<<"compression">>, fun ls_package:compression/2}
              ], UUID, Data),
            [ls_package:add_requirement(UUID, fifo_dt:js2req(R))
             || R <- jsxd:get(<<"requirements">>, [], Data)],
            [ls_package:org_resource_inc(UUID, R, V)
             || {R, V} <- jsxd:get(<<"org">>, [], Data)],
            e2qc:teardown(?LIST_CACHE),
            e2qc:teardown(?FULL_CACHE),
            {{true, <<"/api/", Version/binary, "/packages/", UUID/binary>>},
             Req, State#state{body = Data}};
        duplicate ->
            {ok, Req1} = cowboy_req:reply(409, Req),
            {halt, Req1, State}
    end.

%% TODO : This is a icky case it is called after post.

write(Req, State = #state{method = <<"POST">>, path = []}, _) ->
    {true, Req, State};

write(Req, State = #state{path = [?UUID(Package), <<"metadata">> | Path]},
      [{K, V}]) ->
    ok = ls_package:set_metadata(Package, [{Path ++ [K], jsxd:from_list(V)}]),
    e2qc:evict(?CACHE, Package),
    e2qc:teardown(?FULL_CACHE),
    {true, Req, State};

write(Req, State, _Body) ->
    {false, Req, State}.

%%--------------------------------------------------------------------
%% DEETE
%%--------------------------------------------------------------------

delete(Req, State = #state{path = [?UUID(Package), <<"metadata">> | Path]}) ->
    ok = ls_package:set_metadata(Package, [{Path, delete}]),
    e2qc:evict(?CACHE, Package),
    e2qc:teardown(?FULL_CACHE),
    {true, Req, State};

delete(Req, State = #state{path = [?UUID(Package)]}) ->
    ok = ls_package:delete(Package),
    e2qc:evict(?CACHE, Package),
    e2qc:teardown(?LIST_CACHE),
    e2qc:teardown(?FULL_CACHE),
    {true, Req, State}.

%%--------------------------------------------------------------------
%% Internal
%%--------------------------------------------------------------------

do_set([], _UUID, _O) ->
    ok;
do_set([{K, F} | R], UUID, O) ->
    case jsxd:get([K], O) of
        {ok, V}  ->
            F(UUID, V);
        _ ->
            ok
    end,
    do_set(R, UUID, O).
