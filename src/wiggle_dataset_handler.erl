%% Feel free to use, reuse and abuse the code in this file.

%% @doc Hello world handler.
-module(wiggle_dataset_handler).

-include("wiggle.hrl").
-define(CACHE, dataset).
-define(LIST_CACHE, dataset_list).
-define(FULL_CACHE, dataset_full_list).
-define(CHUNK_SIZE, 5242880).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-behaviour(wiggle_rest_handler).

-export([allowed_methods/3,
         get/1,
         permission_required/1,
         read/2,
         create/3,
         write/3,
         delete/2,
         raw_body/1,
         content_types_accepted/1,
         content_types_provided/1]).

-ignore_xref([content_types_accepted/1,
              content_types_provided/1,
              raw_body/1]).

-define(WRETRY, 5).

allowed_methods(_Version, _Token, []) ->
    [<<"GET">>, <<"POST">>];

allowed_methods(_Version, _Token, [?UUID(_Dataset)]) ->
    [<<"GET">>, <<"DELETE">>, <<"PUT">>, <<"POST">>];

allowed_methods(_Version, _Token, [?UUID(_Dataset), <<"dataset.gz">>]) ->
    [<<"PUT">>, <<"GET">>];

allowed_methods(_Version, _Token, [?UUID(_Dataset), <<"dataset.bz2">>]) ->
    [<<"PUT">>, <<"GET">>];

allowed_methods(<<"0.2.0">>, _Token, [?UUID(_Dataset), <<"networks">>, _]) ->
    [<<"PUT">>, <<"DELETE">>];

allowed_methods(<<"0.1.0">>, _Token, [?UUID(_Dataset), <<"networks">>]) ->
    [<<"PUT">>];

allowed_methods(_Version, _Token, [?UUID(_Dataset), <<"metadata">>|_]) ->
    [<<"PUT">>, <<"DELETE">>].

get(State = #state{path = [?UUID(Dataset) | _]}) ->
    Start = now(),
    R = case application:get_env(wiggle, dataset_ttl) of
            {ok, {TTL1, TTL2}} ->
                wiggle_handler:timeout_cache_with_invalid(
                  ?CACHE, Dataset, TTL1, TTL2, not_found,
                  fun() -> ls_dataset:get(Dataset) end);
            _ ->
                ls_dataset:get(Dataset)
        end,
    ?MSniffle(?P(State), Start),
    R;

get(_State) ->
    not_found.


permission_required(#state{method = <<"POST">>, path = []}) ->
    {ok, [<<"cloud">>, <<"datasets">>, <<"create">>]};

permission_required(#state{path = []}) ->
    {ok, [<<"cloud">>, <<"datasets">>, <<"list">>]};

permission_required(#state{method = <<"GET">>, path = [?UUID(Dataset)]}) ->
    {ok, [<<"datasets">>, Dataset, <<"get">>]};

permission_required(#state{method = <<"PUT">>, path = [?UUID(Dataset)]}) ->
    {ok, [<<"datasets">>, Dataset, <<"edit">>]};

permission_required(#state{method = <<"POST">>, path = [?UUID(Dataset)]}) ->
    {ok, [<<"datasets">>, Dataset, <<"create">>]};

permission_required(#state{method = <<"GET">>, path = [?UUID(Dataset), <<"dataset.gz">>]}) ->
    {ok, [<<"datasets">>, Dataset, <<"create">>]};

permission_required(#state{method = <<"GET">>, path = [?UUID(Dataset), <<"dataset.bz2">>]}) ->
    {ok, [<<"datasets">>, Dataset, <<"export">>]};

permission_required(#state{method = <<"PUT">>, path = [?UUID(Dataset), <<"dataset.gz">>]}) ->
    {ok, [<<"datasets">>, Dataset, <<"create">>]};

permission_required(#state{method = <<"PUT">>, path = [?UUID(Dataset), <<"dataset.bz2">>]}) ->
    {ok, [<<"datasets">>, Dataset, <<"create">>]};

permission_required(#state{method = <<"DELETE">>, path = [?UUID(Dataset)]}) ->
    {ok, [<<"datasets">>, Dataset, <<"delete">>]};

permission_required(#state{method = <<"PUT">>, version = <<"0.1.0">>,
                           path = [?UUID(Dataset), <<"networks">>]}) ->
    {ok, [<<"datasets">>, Dataset, <<"edit">>]};

permission_required(#state{method = <<"PUT">>, version = <<"0.2.0">>,
                           path = [?UUID(Dataset), <<"networks">>, _]}) ->
    {ok, [<<"datasets">>, Dataset, <<"edit">>]};

permission_required(#state{method = <<"DELETE">>, version = <<"0.1.0">>,
                           path = [?UUID(Dataset), <<"networks">>, _]}) ->
    {ok, [<<"datasets">>, Dataset, <<"edit">>]};

permission_required(#state{method = <<"PUT">>, path = [?UUID(Dataset), <<"metadata">> | _]}) ->
    {ok, [<<"datasets">>, Dataset, <<"edit">>]};

permission_required(#state{method = <<"DELETE">>, path = [?UUID(Dataset), <<"metadata">> | _]}) ->
    {ok, [<<"datasets">>, Dataset, <<"edit">>]};

permission_required(_State) ->
    undefined.


raw_body(#state{path=[_, <<"dataset.gz">>], method = <<"PUT">>}) ->
    true;
raw_body(_) ->
    false.

content_types_accepted(#state{path=[_, <<"dataset.gz">>], method = <<"PUT">>}) ->
    [
     {{<<"application">>, <<"x-gzip">>, '*'}, write}
    ];
content_types_accepted(_) ->
    wiggle_handler:accepted().

content_types_provided(#state{path=[_, <<"dataset.gz">>], method = <<"GET">>}) ->
    [
     {{<<"application">>, <<"x-gzip">>, []}, read}
    ];
content_types_provided(_) ->
    wiggle_handler:provided().

%%--------------------------------------------------------------------
%% GET
%%--------------------------------------------------------------------

read(Req, State = #state{token = Token, path = [], full_list=FullList, full_list_fields=Filter}) ->
    Start = now(),
    {ok, Permissions} = wiggle_handler:get_permissions(Token),
    ?MSnarl(?P(State), Start),
    Start1 = now(),
    Permission = [{must, 'allowed',
                   [<<"datasets">>, {<<"res">>, <<"uuid">>}, <<"get">>],
                   Permissions}],
    Res = wiggle_handler:list(fun ls_dataset:list/2,
                              fun ft_dataset:to_json/1, Token, Permission,
                              FullList, Filter, dataset_list_ttl, ?FULL_CACHE,
                              ?LIST_CACHE),

    ?MSniffle(?P(State), Start1),
    {Res, Req, State};

read(Req, State = #state{path = [?UUID(_Dataset)], obj = Obj}) ->
    {ft_dataset:to_json(Obj), Req, State};

read(Req, State = #state{path = [UUID, <<"dataset.gz">>], obj = _Obj}) ->
    {ok, {Host, Port, AKey, SKey, Bucket}} = libsniffle:s3(image),
    Config = [{host, Host},
              {port, Port},
              {chunk_size, ?CHUNK_SIZE},
              {bucket, Bucket},
              {access_key, AKey},
              {secret_key, SKey}],
    {ok, D} = fifo_s3_download:new(UUID, Config),
    StreamFun = fun(SendChunk) ->
                        do_strea(SendChunk, D)
                end,
    {{chunked, StreamFun}, Req, State}.

%%--------------------------------------------------------------------
%% POST
%%--------------------------------------------------------------------

create(Req, State = #state{path = [UUID], version = Version}, Decoded) ->
    case ls_dataset:create(UUID) of
        duplicate ->
            {false, Req, State};
        _ ->
            e2qc:teardown(?LIST_CACHE),
            e2qc:teardown(?FULL_CACHE),
            import_manifest(UUID, Decoded),
            ls_dataset:imported(UUID, 0),
            ls_dataset:status(UUID, <<"pending">>),
            {{true, <<"/api/", Version/binary, "/datasets/", UUID/binary>>},
             Req, State#state{body = Decoded}}
    end;

create(Req, State = #state{path = [], version = Version}, Decoded) ->
    e2qc:teardown(?LIST_CACHE),
    e2qc:teardown(?FULL_CACHE),
    case jsxd:from_list(Decoded) of
        [{<<"url">>, URL}] ->
            Start = now(),
            {ok, UUID} = ls_dataset:import(URL),
            ?MSniffle(?P(State), Start),
            {{true, <<"/api/", Version/binary, "/datasets/", UUID/binary>>}, Req, State#state{body = Decoded}};
        [{<<"config">>, Config},
         {<<"snapshot">>, Snap},
         {<<"vm">>, Vm}] ->
            Start1 = now(),
            {ok, UUID} = ls_vm:promote_snapshot(Vm, Snap, Config),
            ?MSniffle(?P(State), Start1),
            {{true, <<"/api/", Version/binary, "/datasets/", UUID/binary>>}, Req, State#state{body = Decoded}}
    end.

%%--------------------------------------------------------------------
%% PUT
%%--------------------------------------------------------------------

write(Req, State = #state{path = [UUID, <<"dataset.gz">>]}, _) ->
    case ls_dataset:get(UUID) of
        {ok, R} ->
            Size = ft_dataset:image_size(R),
            ls_dataset:status(UUID, <<"importing">>),
            {Res, Req1} = import_dataset(UUID, 0, ensure_integer(Size), Req),
            {Res, Req1, State};
        _ ->
            {false, Req, State}
    end;

write(Req, State = #state{path = [?UUID(Dataset), <<"metadata">> | Path]}, [{K, V}]) ->
    Start = now(),
    ok = ls_dataset:set_metadata(Dataset, [{Path ++ [K], jsxd:from_list(V)}]),
    e2qc:evict(?CACHE, Dataset),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

write(Req, State = #state{path = [?UUID(Dataset), <<"networks">>, NIC],
                          obj = Obj, version = <<"0.2.0">>},
      [{<<"description">>, Desc}]) ->
    Start = now(),
    [ls_dataset:remove_network(Dataset, E) || E = {_NIC, _} <- ft_dataset:networks(Obj),
                                          _NIC =:= NIC],
    ls_dataset:add_network(Dataset, {NIC, Desc}),
    e2qc:evict(?CACHE, Dataset),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {true, Req, State};


write(Req, State = #state{path = [?UUID(Dataset), <<"networks">>],
                          version = <<"0.1.0">>}, Data) ->
    Start = now(),
    Nets =
        ordsets:from_list(
          [{Name, Desc} ||
              [{<<"description">>, Desc}, {<<"name">>, Name}] <- Data]),
    {ok, D} = ls_dataset:get(Dataset),
    OldNets = ordsets:from_list(ft_dataset:networks(D)),
    ToAdd = ordsets:subtract(Nets, OldNets),
    ToDelete = ordsets:subtract(OldNets, Nets),
    [ls_dataset:add_network(Dataset, Nic) || Nic <- ToAdd],
    [ls_dataset:remove_network(Dataset, Nic) || Nic <- ToDelete],
    e2qc:evict(?CACHE, Dataset),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

write(Req, State = #state{path = [?UUID(_Dataset)]}, [{_K, _V}]) ->
    %%Start = now(),
    %% TODO: Cut this down in smaller pices.
    %%ok = libsniffle:dataset_set(Dataset, [K], jsxd:from_list(V)),
    %%e2qc:evict(?CACHE, Dataset),
    %%e2qc:teardown(?FULL_CACHE),
    %%?MSniffle(?P(State), Start),
    {true, Req, State};

write(Req, State = #state{path = []}, _Body) ->
    {true, Req, State};

write(Req, State, _Body) ->
    {false, Req, State}.

%%--------------------------------------------------------------------
%% DELETE
%%--------------------------------------------------------------------

delete(Req, State = #state{path = [?UUID(Dataset), <<"metadata">> | Path]}) ->
    Start = now(),
    ok = ls_dataset:set_metadata(Dataset, [{Path, delete}]),
    e2qc:evict(?CACHE, Dataset),
    e2qc:teardown(?FULL_CACHE),
    ?MSniffle(?P(State), Start),
    {true, Req, State};

delete(Req, State = #state{path = [?UUID(Dataset)]}) ->
    Start = now(),
    case ls_dataset:get(Dataset) of
        {ok, D} ->
            case ft_dataset:status(D) of
                <<"importing">> ->
                    ?MSniffle(?P(State), Start),
                    {409, Req, State};
                _ ->
                    ls_dataset:delete(Dataset),
                    e2qc:evict(?CACHE, Dataset),
                    e2qc:teardown(?LIST_CACHE),
                    e2qc:teardown(?FULL_CACHE),
                    ?MSniffle(?P(State), Start),
                    {true, Req, State}
            end;
        _ ->
            {404, Req, State}
    end.

%%--------------------------------------------------------------------
%% Internal
%%--------------------------------------------------------------------

do_import([], _UUID, _O) ->
    ok;

do_import([{K, F} | R], UUID, O) ->
    case jsxd:get([K], O) of
        {ok, V}  ->
            F(UUID, V);
        _ ->
            ok
    end,
    do_import(R, UUID, O).

import_manifest(UUID, D1) ->
    do_import(
      [
       {<<"metadata">>, fun ls_dataset:set_metadata/2},
       {<<"name">>, fun ls_dataset:name/2},
       {<<"version">>, fun ls_dataset:version/2},
       {<<"description">>, fun ls_dataset:description/2},
       {<<"disk_driver">>, fun ls_dataset:disk_driver/2},
       {<<"nic_driver">>, fun ls_dataset:nic_driver/2},
       {<<"users">>, fun ls_dataset:users/2},
       {[<<"tags">>, <<"kernel_version">>], fun ls_dataset:kernel_version/2}
      ], UUID, D1),
    ls_dataset:image_size(
      UUID,
      ensure_integer(
        jsxd:get(<<"image_size">>,
                 jsxd:get([<<"files">>, 0, <<"size">>], 0, D1), D1))),
    RS = jsxd:get(<<"requirements">>, [], D1),
    Networks = jsxd:get(<<"networks">>, [], RS),
    [ls_dataset:add_network(UUID, {NName, NDesc}) ||
        [{<<"description">>, NDesc}, {<<"name">>, NName}] <- Networks],
    case jsxd:get(<<"homepage">>, D1) of
        {ok, HomePage} ->
            ls_dataset:set_metadata(
              UUID,
              [{<<"homepage">>, HomePage}]);
        _ ->
            ok
    end,
    case jsxd:get(<<"min_platform">>, RS) of
        {ok, Min} ->
            Min1 = [V || {_, V} <- Min],
            [M | _] = lists:sort(Min1),
            R = {must, '>=', <<"sysinfo.Live Image">>, M},
            ls_dataset:add_requirement(UUID, R);
        _ ->
            ok
    end,
    case jsxd:get(<<"os">>, D1) of
        {ok, <<"smartos">>} ->
            ls_dataset:os(UUID, <<"smartos">>),
            ls_dataset:type(UUID, <<"zone">>);
        {ok, OS} ->
            case jsxd:get(<<"type">>, D1) of
                {ok, <<"lx-dataset">>} ->
                    ls_dataset:os(UUID, OS),
                    ls_dataset:type(UUID, <<"zone">>),
                    ls_dataset:zone_type(UUID, <<"lx">>);
                _ ->
                    ls_dataset:os(UUID, OS),
                    ls_dataset:type(UUID, <<"kvm">>)
            end
    end.

import_dataset(UUID, Idx, TotalSize, Req) ->
    {ok, {Host, Port, AKey, SKey, Bucket}} = libsniffle:s3(image),

    ChunkSize = ?CHUNK_SIZE,
    {ok, Upload} = fifo_s3_upload:new(AKey, SKey, Host, Port,
                                      Bucket, UUID),
    Ctx = crypto:hash_init(sha),
    import_dataset_s3(UUID, Idx, TotalSize, {more, Req},
                      ChunkSize, Upload, Ctx, <<>>).



import_dataset_s3(UUID, Idx, TotalSize, {State, Req}, ChunkSize, Upload, Ctx,
                  Acc)
  when byte_size(Acc) >= ChunkSize ->
    <<Chunk:ChunkSize/binary, Acc1/binary>> = Acc,
    case fifo_s3_upload:part(Upload, binary:copy(Chunk)) of
        ok ->
            Idx1 = Idx + 1,
            Done = (Idx1 * ChunkSize) / TotalSize,
            ls_dataset:imported(UUID, Done),
            import_dataset_s3(UUID, Idx1, TotalSize, {State, Req},
                              ChunkSize, Upload, Ctx, Acc1);
        {error, E} ->
            fifo_s3_upload:abort(Upload),
            lager:error("Upload error: ~p", [E]),
            ls_dataset:status(UUID, <<"failed">>),
            {false, Req}

    end;

import_dataset_s3(UUID, _Idx, _TotalSize, {ok, Req},
                  _ChunkSize, Upload, Ctx, Acc) ->
    case fifo_s3_upload:part(Upload, binary:copy(Acc)) of
        ok ->
            fifo_s3_upload:done(Upload),
            ls_dataset:imported(UUID, 1),

            {ok, D} = ls_dataset:get(UUID),
            SHA1 = ft_dataset:sha1(D),
            case base16:encode(crypto:hash_final(Ctx)) of
                Digest when Digest == SHA1 ->
                    ls_dataset:status(UUID, <<"imported">>),
                    {true, Req};
                Digest when SHA1 == <<>> ->
                    ls_dataset:sha1(UUID, Digest),
                    ls_dataset:status(UUID, <<"imported">>),
                    {true, Req};
                Digest ->
                    ls_dataset:sha1(UUID, Digest),
                    ls_dataset:status(UUID, <<"imported">>),
                    {false, Req}
            end;
        {error, E} ->
            fifo_s3_upload:abort(Upload),
            lager:error("Upload error: ~p", [E]),
            ls_dataset:status(UUID, <<"failed">>),
            {false, Req}
    end;


import_dataset_s3(UUID, Idx, TotalSize, {more, Req}, ChunkSize, Upload, Ctx,
                  Acc) ->
    {State, Data, Req1} = cowboy_req:body(Req, []),
    Ctx1 = crypto:hash_update(Ctx, Data),
    Acc1 = <<Acc/binary, Data/binary>>,
    import_dataset_s3(UUID, Idx, TotalSize, {State, Req1},
                      ChunkSize, Upload, Ctx1, Acc1).

ensure_integer(I) when is_integer(I) ->
    I;
ensure_integer(L) when is_list(L) ->
    list_to_integer(L);
ensure_integer(B) when is_binary(B) ->
    list_to_integer(binary_to_list(B)).

do_strea(SendChunk, D) ->
    case fifo_s3_download:get(D) of
        {ok, done} ->
            ok;
        {ok, Data} ->
            SendChunk(binary:copy(Data)),
            do_strea(SendChunk,D)
    end.
