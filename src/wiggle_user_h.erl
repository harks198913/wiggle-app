-module(wiggle_user_h).
-include("wiggle.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-define(CACHE, user).
-define(LIST_CACHE, user_list).
-define(FULL_CACHE, user_full_list).

-export([allowed_methods/3,
         get/1,
         permission_required/2,
         read/2,
         create/3,
         write/3,
         delete/2,
         to_json/1,
         schema/1]).

-behaviour(wiggle_rest_h).

allowed_methods(_V, _Token, []) ->
    [<<"GET">>, <<"POST">>];

allowed_methods(_V, _Token, [?UUID(_User)]) ->
    [<<"GET">>, <<"PUT">>, <<"DELETE">>];

allowed_methods(_V, _Token, [?UUID(_User), <<"metadata">> | _]) ->
    [<<"PUT">>, <<"DELETE">>];

allowed_methods(_V, _Token, [?UUID(_User), <<"tokens">>]) ->
    [<<"POST">>];

allowed_methods(_V, _Token, [?UUID(_User), <<"tokens">>, _TokenID]) ->
    [<<"DELETE">>];

allowed_methods(_V, _Token, [?UUID(_User), <<"keys">>]) ->
    [<<"PUT">>];

allowed_methods(_Version, _Token, [?UUID(_User), <<"keys">>, _]) ->
    [<<"DELETE">>];

allowed_methods(_V, _Token, [?UUID(_User), <<"yubikeys">>]) ->
    [<<"PUT">>];

allowed_methods(_V, _Token, [?UUID(_User), <<"yubikeys">>, _]) ->
    [<<"DELETE">>];

allowed_methods(_V, _Token, [?UUID(_User), <<"permissions">> | _Permission]) ->
    [<<"PUT">>, <<"DELETE">>, <<"GET">>];

allowed_methods(_V, _Token, [?UUID(_User), <<"roles">>, _Role]) ->
    [<<"PUT">>, <<"DELETE">>];

allowed_methods(_V, _Token, [?UUID(_User), <<"orgs">>, _Org]) ->
    [<<"PUT">>, <<"DELETE">>].


%% If we GET on a permission we don't want to know if the user has THIS
%% exact permission, we're fine knowing that he exists, this is used to
%% perform permission checks this way.
get(State = #state{method = <<"GET">>,
                   path = [?UUID(User), <<"permissions">> | _]}) ->
    wiggle_user_h:get(State#state{path = [?UUID(User)]});

get(State = #state{path = [?UUID(User), <<"permissions">> | Permission]}) ->
    case {Permission,
          wiggle_user_h:get(State#state{path = [?UUID(User)]})} of
        {_, not_found} ->
            not_found;
        {[], {ok, Obj}} ->
            {ok, Obj};
        {P, {ok, Obj}} ->
            case lists:member(P, ft_user:permissions(Obj)) of
                true ->
                    {ok, Obj};
                _ ->
                    not_found
            end
    end;

get(State = #state{method = <<"DELETE">>,
                   path = [?UUID(User), <<"roles">>, Role]}) ->
    case wiggle_user_h:get(State#state{path = [?UUID(User)]}) of
        not_found ->
            not_found;
        {ok, Obj} ->
            case lists:member(Role, ft_user:roles(Obj)) of
                true ->
                    {ok, Obj};
                _ ->
                    not_found
            end
    end;

get(State = #state{method = <<"PUT">>,
                   path = [?UUID(User), <<"roles">>, Role]}) ->
    case wiggle_user_h:get(State#state{path = [?UUID(User)]}) of
        not_found ->
            not_found;
        {ok, Obj} ->
            Start1 = erlang:system_time(micro_seconds),
            case ls_role:get(Role) of
                not_found ->
                    ?MSnarl(?P(State), Start1),
                    not_found;
                {ok, _} ->
                    ?MSnarl(?P(State), Start1),
                    {ok, Obj}
            end
    end;

get(State = #state{method = <<"DELETE">>,
                   path = [?UUID(User), <<"tokens">>, Tkn]}) ->
    case wiggle_user_h:get(State#state{path = [?UUID(User)]}) of
        not_found ->
            not_found;
        {ok, Obj} ->
            case ft_user:get_token_by_id(Tkn, Obj) of
                not_found ->
                    not_found;
                _ ->
                    {ok, Obj}
            end
    end;

get(State = #state{path = [?UUID(User) | _]}) ->
    Start = erlang:system_time(micro_seconds),
    R = case application:get_env(wiggle, user_ttl) of
            {ok, {TTL1, TTL2}} ->
                wiggle_h:timeout_cache_with_invalid(
                  ?CACHE, User, TTL1, TTL2, not_found,
                  fun() -> ls_user:get(User) end);
            _ ->
                ls_user:get(User)
        end,
    ?MSnarl(?P(State), Start),
    R.

permission_required(get, []) ->
    {ok, [<<"cloud">>, <<"users">>, <<"list">>]};

permission_required(post, []) ->
    {ok, [<<"cloud">>, <<"users">>, <<"create">>]};

permission_required(get, [?UUID(User)]) ->
    {ok, [<<"users">>, User, <<"get">>]};

permission_required(put, [?UUID(User)]) ->
    {ok, [<<"users">>, User, <<"passwd">>]};

permission_required(delete, [?UUID(User)]) ->
    {ok, [<<"users">>, User, <<"delete">>]};

permission_required(get, [?UUID(User), <<"permissions">> | _]) ->
    {ok, [<<"users">>, User, <<"get">>]};

permission_required(post, [?UUID(User), <<"tokens">>]) ->
    {ok, [<<"users">>, User, <<"edit">>]};

permission_required(delete, [?UUID(User), <<"tokens">>, _Token]) ->
    {ok, [<<"users">>, User, <<"edit">>]};

permission_required(put, [?UUID(User), <<"permissions">> | Permission]) ->
    {multiple, [[<<"users">>, User, <<"grant">>], Permission]};

permission_required(delete, [?UUID(User), <<"permissions">> | Permission]) ->
    {multiple, [[<<"users">>, User, <<"revoke">>], Permission]};


permission_required(put, [?UUID(User), <<"roles">>, Role]) ->
    {multiple, [[<<"users">>, User, <<"join">>],
                [<<"roles">>, Role, <<"join">>]]};

permission_required(delete, [?UUID(User), <<"roles">>, Role]) ->
    {multiple, [[<<"users">>, User, <<"leave">>],
                [<<"roles">>, Role, <<"leave">>]]};

permission_required(put, [?UUID(User), <<"orgs">>, Org]) ->
    {multiple, [[<<"users">>, User, <<"join">>],
                [<<"orgs">>, Org, <<"join">>]]};

permission_required(delete, [?UUID(User), <<"orgs">>, Org]) ->
    {multiple, [[<<"users">>, User, <<"leave">>],
                [<<"orgs">>, Org, <<"leave">>]]};

permission_required(put, [?UUID(User), <<"metadata">> | _]) ->
    {ok, [<<"users">>, User, <<"edit">>]};

permission_required(delete, [?UUID(User), <<"metadata">> | _]) ->
    {ok, [<<"users">>, User, <<"edit">>]};

permission_required(put, [?UUID(User), <<"keys">>]) ->
    {ok, [<<"users">>, User, <<"edit">>]};

permission_required(delete, [?UUID(User), <<"keys">>, _KeyID]) ->
    {ok, [<<"users">>, User, <<"edit">>]};

permission_required(put, [?UUID(User), <<"yubikeys">>]) ->
    {ok, [<<"users">>, User, <<"edit">>]};

permission_required(delete, [?UUID(User), <<"yubikeys">>, _KeyID]) ->
    {ok, [<<"users">>, User, <<"edit">>]};

permission_required(_Method, _Path) ->
    undefined.

%%--------------------------------------------------------------------
%% Schema
%%--------------------------------------------------------------------

%% Add SSH key
schema(#state{method = <<"PUT">>, path = [?UUID(_User), <<"keys">>]}) ->
    user_add_key;

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
                   [<<"users">>, {<<"res">>, <<"uuid">>}, <<"get">>],
                   Permissions}],
    Res = wiggle_h:list(fun ls_user:list/2,
                        fun to_json/1, Token, Permission,
                        FullList, Filter, user_list_ttl, ?FULL_CACHE,
                        ?LIST_CACHE),

    ?MSnarl(?P(State), Start1),
    {Res, Req, State};

read(Req, State = #state{path = [_User], obj = UserObj}) ->
    UserObj2 = to_json(UserObj),
    {UserObj2, Req, State};

read(Req, State = #state{path = [User, <<"permissions">> | Permission]}) ->
    case wiggle_h:get_permissions(User) of
        not_found ->
            {ok, Req1} = cowboy_req:reply(404, Req),
            {halt, Req1, State};
        {ok, Ps} ->
            case libsnarl:test(Permission, Ps) of
                true ->
                    {[{<<"ok">>, <<"allowed">>}], Req, State};
                false ->
                    {[{<<"error">>, <<"forbidden">>}], Req, State}
            end
    end.

%%--------------------------------------------------------------------
%% POST
%%--------------------------------------------------------------------

create(Req, State = #state{token = Token, path = [], version = Version},
       [{<<"password">>, Pass}, {<<"user">>, User}]) ->
    {ok, Creator} = ls_user:get(Token),
    CUUID = ft_user:uuid(Creator),
    Start = erlang:system_time(micro_seconds),
    {ok, UUID} = ls_user:add(CUUID, User),
    ?MSnarl(?P(State), Start),
    Start1 = erlang:system_time(micro_seconds),
    ok = ls_user:passwd(UUID, Pass),
    e2qc:teardown(?LIST_CACHE),
    e2qc:teardown(?FULL_CACHE),
    ?MSnarl(?P(State), Start1),
    {{true, <<"/api/", Version/binary, "/users/", UUID/binary>>}, Req, State};

create(Req, State = #state{path = [?UUID(User), <<"tokens">>], version = ?V2},
       [{<<"comment">>, Comment}, {<<"scope">>, Scope}]) ->
    case ls_user:api_token(User, Scope, Comment) of
        not_found ->
            {ok, Req1} = cowboy_req:reply(404, [], <<"User not found">>, Req),
            {halt, Req1, State};
        {error, bad_scope} ->
            {ok, Req1} = cowboy_req:reply(404, [], <<"Bad scope">>, Req),
            {halt, Req1, State};
        {ok, {TokenID, Token}} ->
            e2qc:evict(?CACHE, User),
            e2qc:teardown(?FULL_CACHE),
            {MediaType, Req1} =
                case cowboy_req:meta(media_type, Req) of
                    {{<<"application">>, <<"x-msgpack">>, _}, ReqX} ->
                        {msgpack, ReqX};
                    {{<<"application">>, <<"json">>, _}, ReqX} ->
                        {json, ReqX}
                end,
            J = [{<<"token">>, Token}, {<<"token-id">>, TokenID}],
            {Body, Req2} = wiggle_h:encode(J, MediaType, Req1),
            {ok, Req3} = cowboy_req:reply(200, [], Body, Req2),
            {halt, Req3, State}
    end;

create(Req, State = #state{path = [?UUID(User), <<"tokens">>], version = ?V2},
       [{<<"comment">>, Comment}, {<<"csr">>, CSR}, {<<"scope">>, Scope}]) ->
    case ls_user:sign_csr(User, Scope, Comment, CSR) of
        not_found ->
            {ok, Req1} = cowboy_req:reply(404, [], <<"User not found">>, Req),
            {halt, Req1, State};
        {error, bad_scope} ->
            {ok, Req1} = cowboy_req:reply(404, [], <<"Bad scope">>, Req),
            {halt, Req1, State};
        {ok, {TokenID, Cert}} ->
            e2qc:evict(?CACHE, User),
            e2qc:teardown(?FULL_CACHE),
            {MediaType, Req1} =
                case cowboy_req:meta(media_type, Req) of
                    {{<<"application">>, <<"x-msgpack">>, _}, ReqX} ->
                        {msgpack, ReqX};
                    {{<<"application">>, <<"json">>, _}, ReqX} ->
                        {json, ReqX}
                end,
            J = [{<<"cert">>, Cert}, {<<"token-id">>, TokenID}],
            {Body, Req2} = wiggle_h:encode(J, MediaType, Req1),
            {ok, Req3} = cowboy_req:reply(200, [], Body, Req2),
            {halt, Req3, State}
    end.


%%--------------------------------------------------------------------
%% Put
%%--------------------------------------------------------------------

write(Req,
      State = #state{path =  [?UUID(User)]}, [{<<"password">>, Password}]) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_user:passwd(User, Password),
    ?MSnarl(?P(State), Start),
    {true, Req, State};

%% TODO : This is a icky case it is called after post.
write(Req, State = #state{method = <<"POST">>, path = []}, _) ->
    {true, Req, State};

write(Req, State = #state{path = [?UUID(User), <<"metadata">> | Path]},
      [{K, V}]) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_user:set_metadata(User, [{[<<"public">> | Path] ++ [K],
                                      jsxd:from_list(V)}]),
    e2qc:evict(?CACHE, User),
    e2qc:teardown(?FULL_CACHE),
    ?MSnarl(?P(State), Start),
    {true, Req, State};

write(Req, State = #state{path = [?UUID(User), <<"keys">>]}, [{KeyID, Key}]) ->
    case re:split(Key, " ") of
        [_, ID, _] ->
            try
                %% We do this to ensure it can be decoded!
                base64:decode(ID),
                Start = erlang:system_time(micro_seconds),
                case ls_user:key_add(User, KeyID, Key) of
                    ok ->
                        e2qc:evict(?CACHE, User),
                        e2qc:teardown(?FULL_CACHE),
                        ?MSnarl(?P(State), Start),
                        {true, Req, State};
                    duplicate ->
                        ?MSnarl(?P(State), Start),
                        lager:error("[ssh] Doublicated key: ~s", [ID]),
                        {ok, Req1} = cowboy_req:reply(409, Req),
                        {halt, Req1, State}
                end
            catch
                _:_ ->
                    lager:error("[ssh] Couldn't base64 decode id: ~s", [ID]),
                    {false, Req, State}
            end;
        _ ->
            {false, Req, State}
    end;

write(Req, State = #state{path = [?UUID(User), <<"yubikeys">>]},
      [{<<"otp">>, <<_:33/binary, _/binary >>= OTP}]) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_user:yubikey_add(User, OTP),
    e2qc:evict(?CACHE, User),
    e2qc:teardown(?FULL_CACHE),
    ?MSnarl(?P(State), Start),
    {true, Req, State};

write(Req, State = #state{path = [_, <<"yubikeys">>]}, _) ->
    {false, Req, State};

write(Req, State = #state{path = [?UUID(User), <<"roles">>, Role]}, _) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_user:join(User, Role),
    e2qc:evict(?CACHE, User),
    e2qc:teardown(?FULL_CACHE),
    ?MSnarl(?P(State), Start),
    {true, Req, State};

write(Req, State = #state{path = [?UUID(User), <<"orgs">>, Org]}, []) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_user:join_org(User, Org),
    e2qc:evict(?CACHE, User),
    e2qc:teardown(?FULL_CACHE),
    ?MSnarl(?P(State), Start),
    {true, Req, State};

write(Req, State = #state{path = [?UUID(User), <<"orgs">>, Org]}, [{}]) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_user:join_org(User, Org),
    e2qc:evict(?CACHE, User),
    e2qc:teardown(?FULL_CACHE),
    ?MSnarl(?P(State), Start),
    {true, Req, State};

write(Req, State = #state{path = [?UUID(User), <<"orgs">>, Org]},
      [{<<"active">>, true}]) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_user:join_org(User, Org),
    ok = ls_user:select_org(User, Org),
    e2qc:evict(?CACHE, User),
    e2qc:teardown(?FULL_CACHE),
    ?MSnarl(?P(State), Start),
    {true, Req, State};

write(Req, State = #state{path = [?UUID(User), <<"permissions">>
                                      | Permission]}, _) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_user:grant(User, Permission),
    e2qc:evict(?CACHE, User),
    e2qc:teardown(?FULL_CACHE),
    ?MSnarl(?P(State), Start),
    {true, Req, State}.


%%--------------------------------------------------------------------
%% DEETE
%%--------------------------------------------------------------------

delete(Req, State = #state{path = [?UUID(User), <<"metadata">> | Path]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_user:set_metadata(User, [{[<<"public">> | Path], delete}]),
    e2qc:evict(?CACHE, User),
    e2qc:teardown(?FULL_CACHE),
    ?MSnarl(?P(State), Start),
    {true, Req, State};

delete(Req, State = #state{path = [?UUID(User), <<"keys">>, KeyID]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_user:key_revoke(User, KeyID),
    e2qc:evict(?CACHE, User),
    e2qc:teardown(?FULL_CACHE),
    ?MSnarl(?P(State), Start),
    {true, Req, State};

delete(Req, State = #state{path = [?UUID(User), <<"yubikeys">>, KeyID]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_user:yubikey_remove(User, KeyID),
    e2qc:evict(?CACHE, User),
    e2qc:teardown(?FULL_CACHE),
    ?MSnarl(?P(State), Start),
    {true, Req, State};

delete(Req, State = #state{path = [_User, <<"sessions">>]}) ->
    Req1 = cowboy_req:set_resp_cookie(<<"x-snarl-token">>, <<"">>,
                                      [{max_age, 0}], Req),
    {true, Req1, State};

delete(Req, State = #state{path = [?UUID(User), <<"permissions">>
                                       | Permission]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_user:revoke(User, Permission),
    e2qc:evict(?CACHE, User),
    e2qc:teardown(?FULL_CACHE),
    ?MSnarl(?P(State), Start),
    {true, Req, State};

delete(Req, State = #state{path = [?UUID(User)]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_user:delete(User),
    e2qc:evict(?CACHE, User),
    e2qc:teardown(?LIST_CACHE),
    e2qc:teardown(?FULL_CACHE),
    ?MSnarl(?P(State), Start),
    {true, Req, State};

delete(Req, State = #state{path = [?UUID(User), <<"orgs">>, Org]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_user:leave_org(User, Org),
    e2qc:evict(?CACHE, User),
    e2qc:teardown(?FULL_CACHE),
    ?MSnarl(?P(State), Start),
    {true, Req, State};

delete(Req, State = #state{path = [?UUID(User), <<"roles">>, Role]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_user:leave(User, Role),
    e2qc:evict(?CACHE, User),
    e2qc:teardown(?FULL_CACHE),
    ?MSnarl(?P(State), Start),
    {true, Req, State};

delete(Req, State = #state{path = [?UUID(User), <<"tokens">>, TokenID]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_user:revoke_token(User, TokenID),
    e2qc:evict(?CACHE, User),
    e2qc:teardown(?FULL_CACHE),
    ?MSnarl(?P(State), Start),
    {true, Req, State}.

%%--------------------------------------------------------------------
%% Internal Functions
%%--------------------------------------------------------------------

to_json(U) ->
    U1 = ft_user:to_json(U),
    U2 = jsxd:delete([<<"password">>], U1),
    jsxd:update([<<"metadata">>],
                fun(M) ->
                        jsxd:get([<<"public">>], [{}], M)
                end, [{}], U2).
