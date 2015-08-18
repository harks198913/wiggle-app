%% {
%%   "client_id":"Client1",
%%   "metadata":{},
%%   "name":"This Cool Test Client",
%%   "permissions":[],
%%   "redirect_uris":["http://client.uri","https://developers.google.com/oauthplayground"],
%%   "roles":[],
%%   "type":"public",
%%   "uuid":"308f8590-bc66-4f6c-bec5-2ff0c01d063c"
%% }

-module(wiggle_client_h).
-include("wiggle.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-define(CACHE, client).
-define(LIST_CACHE, client_list).
-define(FULL_CACHE, client_full_list).

-export([allowed_methods/3,
         get/1,
         permission_required/1,
         read/2,
         create/3,
         write/3,
         delete/2]).

-behaviour(wiggle_rest_h).

allowed_methods(_Version, _Token, []) ->
    [<<"GET">>, <<"POST">>];

allowed_methods(_Version, _Token, [?UUID(_Client)]) ->
    [<<"GET">>, <<"PUT">>, <<"DELETE">>];

allowed_methods(_Version, _Token, [?UUID(_Client), <<"permissions">> | _]) ->
    [<<"PUT">>, <<"DELETE">>];

allowed_methods(_Version, _Token, [?UUID(_Client), <<"uris">>]) ->
    [<<"POST">>];

allowed_methods(_Version, _Token, [?UUID(_Client), <<"uris">>, _]) ->
    [ <<"DELETE">>];

allowed_methods(_Version, _Token, [?UUID(_Client), <<"metadata">> | _]) ->
    [<<"PUT">>, <<"DELETE">>].

get(State = #state{path = [?UUID(Client) | _]}) ->
    Start = erlang:system_time(micro_seconds),
    R = case application:get_env(wiggle, client_ttl) of
            {ok, {TTL1, TTL2}} ->
                wiggle_h:timeout_cache_with_invalid(
                  ?CACHE, Client, TTL1, TTL2, not_found,
                  fun() -> ls_client:get(Client) end);
            _ ->
                ls_client:get(Client)
        end,
    ?MSnarl(?P(State), Start),
    R.

permission_required(#state{method = <<"GET">>, path = []}) ->
    {ok, [<<"cloud">>, <<"clients">>, <<"list">>]};

permission_required(#state{method = <<"POST">>, path = []}) ->
    {ok, [<<"cloud">>, <<"clients">>, <<"create">>]};

permission_required(#state{method = <<"GET">>, path = [?UUID(Client)]}) ->
    {ok, [<<"clients">>, Client, <<"get">>]};

permission_required(#state{method = <<"PUT">>, path = [?UUID(Client)]}) ->
    {ok, [<<"clients">>, Client, <<"edit">>]};

permission_required(#state{method = <<"DELETE">>, path = [?UUID(Client)]}) ->
    {ok, [<<"clients">>, Client, <<"delete">>]};

permission_required(#state{method = <<"PUT">>,
                           path = [?UUID(Client), <<"permissions">> | _]}) ->
    {ok, [<<"clients">>, Client, <<"grant">>]};

permission_required(#state{method = <<"DELETE">>,
                           path = [?UUID(Client), <<"permissions">> | _]}) ->
    {ok, [<<"clients">>, Client, <<"revoke">>]};

permission_required(#state{method = <<"POST">>,
                           path = [?UUID(Client), <<"uris">>]}) ->
    {ok, [<<"clients">>, Client, <<"edit">>]};

permission_required(#state{method = <<"DELETE">>,
                           path = [?UUID(Client), <<"urls">>, _]}) ->
    {ok, [<<"clients">>, Client, <<"edit">>]};

permission_required(#state{path = [?UUID(Client), <<"metadata">> | _]}) ->
    {ok, [<<"clients">>, Client, <<"edit">>]};

permission_required(_State) ->
    undefined.

%%--------------------------------------------------------------------
%% GET
%%--------------------------------------------------------------------

read(Req, State = #state{token = Token, path = [], full_list=FullList, full_list_fields=Filter}) ->
    Start = erlang:system_time(micro_seconds),
    {ok, Permissions} = wiggle_h:get_permissions(Token),
    ?MSnarl(?P(State), Start),
    Start1 = erlang:system_time(micro_seconds),
    Permission = [{must, 'allowed',
                   [<<"clients">>, {<<"res">>, <<"uuid">>}, <<"get">>],
                   Permissions}],
    Res = wiggle_h:list(fun ls_client:list/2,
                        fun to_json/1, Token, Permission,
                        FullList, Filter, client_list_ttl, ?FULL_CACHE,
                        ?LIST_CACHE),

    ?MSnarl(?P(State), Start1),
    {Res, Req, State};

read(Req, State = #state{path = [_Client], obj = ClientObj}) ->
    ClientObj2 = to_json(ClientObj),
    {ClientObj2, Req, State}.

%%--------------------------------------------------------------------
%% PUT
%%--------------------------------------------------------------------

create(Req, State = #state{token = Token, path = [], version = Version}, Decoded) ->
    {ok, Creator} = ls_user:get(Token),
    CUUID = ft_user:uuid(Creator),
    {ok, Client} = jsxd:get(<<"client">>, Decoded),
    {ok, Pass} = jsxd:get(<<"secret">>, Decoded),
    Start = erlang:system_time(micro_seconds),
    case ls_client:add(CUUID, Client) of
        {ok, UUID} ->
            ?MSnarl(?P(State), Start),
            Start1 = erlang:system_time(micro_seconds),
            ok = ls_client:secret(UUID, Pass),
            e2qc:teardown(?LIST_CACHE),
            e2qc:teardown(?FULL_CACHE),
            ?MSnarl(?P(State), Start1),
            {{true, <<"/api/", Version/binary, "/clients/", UUID/binary>>},
             Req, State#state{body = Decoded}};
        duplicate ->
            ?MSniffle(?P(State), Start),
            {ok, Req1} = cowboy_req:reply(409, Req),
            {halt, Req1, State}
    end.


write(Req, State = #state{path =  [?UUID(Client)]}, [{<<"secret">>, Secret}]) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_client:secret(Client, Secret),
    ?MSnarl(?P(State), Start),
    {true, Req, State};

write(Req, State = #state{path = [?UUID(Client), <<"metadata">> | Path]}, [{K, V}]) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_client:set_metadata(Client, [{[<<"public">> | Path] ++ [K], jsxd:from_list(V)}]),
    e2qc:evict(?CACHE, Client),
    e2qc:teardown(?FULL_CACHE),
    ?MSnarl(?P(State), Start),
    {true, Req, State}.

%%--------------------------------------------------------------------
%% DEETE
%%--------------------------------------------------------------------

delete(Req, State = #state{path = [?UUID(Client), <<"metadata">> | Path]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_client:set_metadata(Client, [{[<<"public">> | Path], delete}]),
    e2qc:evict(?CACHE, Client),
    e2qc:teardown(?FULL_CACHE),
    ?MSnarl(?P(State), Start),
    {true, Req, State};


delete(Req, State = #state{path = [?UUID(Client)]}) ->
    Start = erlang:system_time(micro_seconds),
    ok = ls_client:delete(Client),
    e2qc:evict(?CACHE, Client),
    e2qc:teardown(?LIST_CACHE),
    e2qc:teardown(?FULL_CACHE),
    ?MSnarl(?P(State), Start),
    {true, Req, State}.

%%--------------------------------------------------------------------
%% Internal Functions
%%--------------------------------------------------------------------

to_json(U) ->
    U1 = ft_client:to_json(U),
    U2 = jsxd:delete([<<"secret">>], U1),
    jsxd:update([<<"metadata">>],
                fun(M) ->
                        jsxd:get([<<"public">>], [{}], M)
                end, [{}], U2).
