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
         allowed/2
        ]).

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
    VersionI = case Version of
                   ?V1 -> 1;
                   _ ->
                       try
                           binary_to_integer(Version)
                       catch
                           _:_ ->
                               0
                       end
               end,
    {Path, Req2} = cowboy_req:path_info(Req1),
    {PathB, Req3} = cowboy_req:path(Req2),
    {FullList, Req4} = full_list(Req3),
    {FullListFields, Req5} = full_list_fields(Req4),
    State =  #state{
                version = Version,
                version_i = VersionI,
                method = Method,
                path = Path,
                start = erlang:system_time(micro_seconds),
                path_bin = PathB,
                full_list = FullList,
                full_list_fields = FullListFields
               },
    {State1, Req6} = get_token(State, Req5),
    Req7 = case State1 of
               #state{token = {token, Tkn}} ->
                   cowboy_req:set_resp_header(<<"x-snarl-token">>, Tkn, Req6);
               _ ->
                   Req6
           end,
    {ok, set_access_header(Req7), State1}.

set_access_header(Req) ->
    Req1 = cowboy_req:set_resp_header(
             <<"access-control-allow-origin">>, <<"*">>, Req),
    Req2 = cowboy_req:set_resp_header(
             <<"access-control-allow-headers">>,
             <<"Authorization, content-type, x-snarl-token, x-full-list, x-full-list-fields">>, Req1),
    Req3 = cowboy_req:set_resp_header(
             <<"access-control-expose-headers">>,
             <<"x-snarl-token, x-full-list, x-full-list-fields">>, Req2),
    cowboy_req:set_resp_header(
      <<"access-control-allow-credentials">>, <<"true">>, Req3).


%% We only support the x-snarl-token in the V1 API.
get_token(State = #state{version = ?V1}, Req) ->
    case cowboy_req:header(<<"x-snarl-token">>, Req) of
        {undefined, Req1} ->
            get_header(State, Req1);
        {Token, Req1} ->
            {State#state{token = {token, Token}}, Req1}
    end;

get_token(State, Req) ->
    get_header(State, Req).

%% We only allow basic auth in the V1 API
get_header(State = #state{version = ?V1}, Req) ->
    {ok, Auth, Req1} = cowboy_req:parse_header(<<"authorization">>, Req),
    case Auth of
        {<<"basic">>, {Username, Password}} ->
            case libsnarl:auth(Username, Password) of
                {ok, UUID} ->
                    {State#state{token = UUID}, Req1};
                _ ->
                    {State, Req1}
            end;
        {<<"bearer">>, Bearer} ->
            State1 = resolve_bearer(State#state{bearer = Bearer}),
            {State1, Req1};
        _ ->
            get_qs(State, Req1)
    end;

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

%% We only use cookies in the V1 API
get_cookie(State = #state{version = ?V1}, Req) ->
    case cowboy_req:cookie(<<"x-snarl-token">>, Req) of
        {undefined, Req1} ->
            {State, Req1};
        {Token, Req1} ->
            {State#state{token = {token, Token}}, Req1}
    end;
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
        {undefined, ReqY} ->
            case cowboy_req:header(<<"x-full-list">>, ReqY) of
                {<<"true">>, ReqX} ->
                    {true, ReqX};
                {<<"True">>, ReqX} ->
                    {true, ReqX};
                {_, ReqX} ->
                    {false, ReqX}
            end;
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
            case cowboy_req:header(<<"x-full-list-fields">>, ReqY) of
                {undefined, ReqX} ->
                    {[], ReqX};
                {Fields, ReqX} ->
                    {re:split(Fields, ","), ReqX}
            end;
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

list(ListFn, ConvertFn, Token, Permission, FullList, Filter, TTLEntry, FullCache, ListCache) ->
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
