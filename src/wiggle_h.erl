-module(wiggle_h).

-include("wiggle.hrl").

-export([
         initial_state/1,
         provided/0,
         accepted/0,
         decode/1,
         decode/2,
         get_token/2,
         set_access_header/1,
         options/3,
         service_available/0,
         encode/3,
         get_permissions/1,
         clear_permissions/1,
         timeout_cache_with_invalid/6,
         timeout_cache/5,
         list/9,
         allowed/2,
         get_ws_token/1
        ]).


-type permission() :: [binary()].
-type path() :: [binary()].
-type method() :: get |
                  put |
                  post |
                  delete |
                  update |
                  trace |
                  options |
                  head |
                  connect |
                  undefined.

-export_type([permission/0, method/0, path/0]).

allowed(State=#state{scope_perms = SP}, Permission) ->
    Start = erlang:system_time(micro_seconds),
    R = libsnarlmatch:test_perms(Permission, SP)
        andalso allowed_tkn(Permission, State),
    ?MSnarl(?P(State), Start),
    R.

allowed_tkn(_Permission, #state{token = undefined}) ->
    lager:warning("[auth] no Token for allowed.", []),
    false;
allowed_tkn(Perm, #state{token = Token}) ->
    case get_permissions(Token) of
        not_found ->
            lager:warning("[auth] unknown Token for allowed: ~p", [Token]),
            false;
        {ok, Ps} ->
            libsnarl:test(Perm, Ps)
    end.

initial_state(Req) ->
    {Method, Req0} = cowboy_req:method(Req),
    {Version, Req1} = cowboy_req:binding(version, Req0),
    VersionI = try
                   binary_to_integer(Version)
               catch
                   _:_ ->
                       0
               end,
    MethodA = method_to_atom(Method),
    {Path, Req2} = cowboy_req:path_info(Req1),
    {PathB, Req3} = cowboy_req:path(Req2),
    {FullList, Req4} = full_list(Req3),
    {FullListFields, Req5} = full_list_fields(Req4),
    State =  #state{
                version = Version,
                version_i = VersionI,
                method = Method,
                method_a = MethodA,
                path = Path,
                start = erlang:system_time(micro_seconds),
                path_bin = PathB,
                full_list = FullList,
                full_list_fields = FullListFields
               },
    {State1, Req6} = get_token(State, Req5),
    {ok, set_access_header(Req6), State1}.

method_to_atom(<<"GET">>) ->
    get;
method_to_atom(<<"PUT">>) ->
    put;
method_to_atom(<<"POST">>) ->
    post;
method_to_atom(<<"DELETE">>) ->
    delete;
method_to_atom(<<"UPDATE">>) ->
    update;
method_to_atom(<<"TRACE">>) ->
    trace;
method_to_atom(<<"OPTIONS">>) ->
    options;
method_to_atom(<<"HEAD">>) ->
    head;
method_to_atom(<<"CONNECT">>) ->
    connect;
method_to_atom(_) ->
    undefined.

set_access_header(Req) ->
    Req1 = cowboy_req:set_resp_header(
             <<"access-control-allow-origin">>, <<"*">>, Req),
    Req2 = cowboy_req:set_resp_header(
             <<"access-control-allow-headers">>,
             <<"Authorization, content-type">>,
             Req1),
    cowboy_req:set_resp_header(
      <<"access-control-allow-credentials">>, <<"true">>, Req2).

get_token(State, Req) ->
    get_header(State, Req).

get_header(State, Req) ->
    case cowboy_oauth:get_token(Req) of
        {undefined, Req1} ->
            get_qs(State, Req1);
        {{UUID, _Client, SPerms}, Req1} ->
            {ok, {<<"bearer">>, Bearer}, Req2} =
                cowboy_req:parse_header(<<"authorization">>, Req1),
            {State#state{token = UUID, scope_perms = SPerms, bearer = Bearer},
             Req2}
    end.

%%Handle fifo_ott (One time token) query strings, resolve the OTT to a
%%bearer token and delete it.
get_qs(State, Req) ->
    case cowboy_req:qs_val(<<"fifo_ott">>, Req) of
        {undefined, Req1} ->
            get_cookie(State, Req1);
        {OTT, Req1} ->
            case ls_token:get(OTT) of
                {ok, Bearer} ->
                    ls_token:delete(OTT),
                    State1 = resolve_bearer(State#state{bearer = Bearer}),
                    {State1, Req1};
                _ ->
                    get_cookie(State, Req1)
            end
    end.

get_cookie(State, Req) ->
    {State, Req}.


resolve_bearer(State = #state{bearer = Bearer}) ->
    case cowboy_oauth:resolve_bearer(Bearer) of
        undefined ->
            State;
        {UUID, _Client, SPerms} ->
            State#state{token = UUID, scope_perms = SPerms}
    end.

full_list(Req) ->
    case cowboy_req:qs_val(<<"full-list">>, Req) of
        {<<"true">>, ReqY} ->
            {true, ReqY};
        {<<"True">>, ReqY} ->
            {true, ReqY};
        {_, ReqY} ->
            {false, ReqY}
    end.

full_list_fields(Req) ->
    case cowboy_req:qs_val(<<"full-list-fields">>, Req) of
        {undefined, ReqY} ->
            {[], ReqY};
        {Fields, ReqY} ->
            {re:split(Fields, ","), ReqY}
    end.

provided() ->
    [
     {{<<"application">>, <<"x-msgpack">>, []}, read_msgpack},
     {{<<"application">>, <<"json">>, []}, read_json}
    ].

accepted() ->
    [
     {{<<"application">>, <<"x-msgpack">>, '*'}, write_msgpack},
     {{<<"application">>, <<"json">>, '*'}, write_json}
    ].

content_type(Req) ->
    case cowboy_req:header(<<"content-type">>, Req) of
        {<<"application/x-msgpack", _/binary>>, Req1} ->
            {msgpack, Req1};
        {<<"application/json", _/binary>>, Req1} ->
            {json, Req1};
        {undefined, Req1} ->
            {json, Req1};
        {Oops, Req1} ->
            lager:info("[content_type] Unknown media_type: ~p", [Oops]),
            {json, Req1}
    end.


decode(Req) ->
    {ContentType, Req0} = content_type(Req),
    decode(Req0, ContentType).

decode(Req, ContentType) ->
    {ok, Body, Req1} = cowboy_req:body(Req),
    Decoded = case Body of
                  <<>> ->
                      [];
                  _ ->
                      case ContentType of
                          json ->
                              jsxd:from_list(jsx:decode(Body));
                          msgpack ->
                              {ok, D} = msgpack:unpack(Body, [jsx]),
                              jsxd:from_list(D)
                      end
              end,
    {ok, Decoded, Req1}.

encode(Body, MediaType, Req) ->
    case MediaType of
        json ->
            {jsx:encode(Body), Req};
        msgpack ->
            {msgpack:pack(Body, [jsx]), Req}
    end.

options(Req, State, Methods) ->
    Req1 = cowboy_req:set_resp_header(
             <<"access-control-allow-methods">>,
             string:join(
               lists:map(fun erlang:binary_to_list/1,
                         [<<"HEAD">>, <<"OPTIONS">> | Methods]), ", "), Req),
    {ok, Req1, State}.


service_available() ->
    case {libsniffle:servers(), libsnarl:servers(),
          application:get_env(wiggle, api, all)} of
        {_, [], _} ->
            false;
        {[], _, all} ->
            false;
        _ ->
            true
    end.

%% Cache user permissions for up to 1s (no refresh on 100ms)
get_permissions(Token) ->
    {TTL1, TTL2} = application:get_env(wiggle, token_ttl,
                                       {1000*100, 1000*1000}),
    timeout_cache(permissions, Token, TTL1, TTL2,
                  fun () -> ls_user:cache(Token) end).

clear_permissions(#state{token = Token}) ->
    e2qc:evict(permissions, Token).

timeout_cache(Cache, Value, TTL1, TTL2, Fun) ->
    case application:get_env(wiggle, caching, true) of
        true ->
            timeout_cache_(Cache, Value, TTL1, TTL2, Fun);
        false ->
            Fun()
    end.

timeout_cache_(Cache, Value, TTL1, TTL2, Fun) ->
    CacheFun = fun() -> {erlang:system_time(milli_seconds), Fun()} end,
    {T0, R} = e2qc:cache(Cache, Value, CacheFun),
    case T0 - erlang:system_time(milli_seconds) of
        Diff when Diff < TTL1 ->
            R;
        Diff when Diff < TTL2 ->
            e2qc:evict(Cache, Value),
            spawn(e2qc, cache, [Cache, Value, CacheFun]),
            R;
        _ ->
            e2qc:evict(Cache, Value),
            {_, R1} = e2qc:cache(Cache, Value, CacheFun),
            R1
    end.

%% This function lets us define a timedout cache with a invalid value
%% this is helpful since we don't want to cache not_found's.
timeout_cache_with_invalid(Cache, Value, TTL1, TTL2, Invalid, Fun) ->
    case timeout_cache(Cache, Value, TTL1, TTL2, Fun) of
        R when R =:= Invalid ->
            e2qc:evict(Cache, Value),
            R;
        R ->
            R
    end.

list(ListFn, ConvertFn, Token, Permission, FullList, Filter, TTLEntry,
     FullCache, ListCache) ->
    Fun = list_fn(ListFn, ConvertFn, Permission, FullList, Filter),
    case application:get_env(wiggle, TTLEntry) of
        {ok, {TTL1, TTL2}} ->
            case FullList of
                true ->
                    timeout_cache(FullCache, {Token, Filter}, TTL1, TTL2, Fun);
                _ ->
                    timeout_cache(ListCache, Token, TTL1, TTL2, Fun)
            end;
        _ ->
            Fun()
    end.

list_fn(ListFn, ConvertFn, Permission, FullList, Filter) ->
    fun () ->
            {ok, Res} = ListFn(Permission, FullList),
            case {Filter, FullList} of
                {_, false} ->
                    [ID || {_, ID} <- Res];
                {[], _} ->
                    [ConvertFn(Obj) || {_, Obj} <- Res];
                _ ->
                    [jsxd:select(Filter, ConvertFn(Obj)) || {_, Obj} <- Res]
            end
    end.

%% Fuck you dialyzer, it refuses to accept that get_token can
%% return stuff other then no_token ...
%% -dialyzer({nowarn_function, [get_token/2]}).
-spec get_ws_token(Req) ->
                       {ok, binary(), [[binary()]], Req} |
                       {denied, Req} |
                       {no_token, Req}
                           when Req :: cowboy_req:req().

get_ws_token(Req) ->
    case cowboy_req:qs_val(<<"fifo_ott">>, Req) of
        {OTT, Req1} when is_binary(OTT) ->
            case ls_token:get(OTT) of
                {ok, Bearer} ->
                    ls_token:delete(OTT),
                    verify_bearer(Bearer, Req1);
                _ ->
                    {denied, Req1}
            end;
        {undefined, Req1} ->
            {no_token, Req1}
    end.

verify_bearer(Bearer, Req)->
    case ls_oauth:verify_access_token(Bearer) of
        {ok, Context} ->
            case {proplists:get_value(<<"resource_owner">>, Context),
                  proplists:get_value(<<"scope">>, Context)} of
                {undefined, _} ->
                    {denied, Req};
                {UUID, Scope} ->
                    {ok, Scopes} = ls_oauth:scope(Scope),
                    SPerms = cowboy_oauth:scope_perms(Scopes, []),
                    {ok, UUID, SPerms, Req}
            end;
        _ ->
            {denied, Req}
    end.
