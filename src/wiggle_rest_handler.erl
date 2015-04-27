-module(wiggle_rest_handler).

-include("wiggle.hrl").

-export([init/3,
         rest_init/2,
         rest_terminate/2]).

-export([content_types_provided/2,
         content_types_accepted/2,
         allowed_methods/2,
         resource_exists/2,
         service_available/2,
         delete_resource/2,
         forbidden/2,
         options/2,
         generate_etag/2,
         is_authorized/2]).

-export([read/2,
         write/2]).

-ignore_xref([read/2,
              write/2,
              allowed_methods/2,
              content_types_accepted/2,
              content_types_provided/2,
              delete_resource/2,
              generate_etag/2,
              forbidden/2,
              init/3,
              rest_terminate/2,
              is_authorized/2,
              options/2,
              service_available/2,
              resource_exists/2,
              rest_init/2,
              behaviour_info/1]).


-type handler_state() :: #state{}.

-callback allowed_methods(Version :: binary(), Token :: binary(),
                          Path :: [binary()]) ->
    [binary()].

-callback get(handler_state()) ->
    not_found | term().

-callback permission_required(handler_state()) ->
    {ok, [binary()] | always} | undefined.

-callback read(Req :: term(), handler_state()) ->
    {term(), Req :: term(), handler_state()}.

-callback create(Req :: term(), handler_state(), jsxd:object()) ->
    {term(), Req :: term(), handler_state()}.

-callback write(Req :: term(), handler_state(), jsxd:object()) ->
    {term(), Req :: term(), handler_state()}.

-callback delete(Req :: term(), handler_state()) ->
    {term(), Req :: term(), handler_state()}.


init(_Transport, _Req, _) ->
    {upgrade, protocol, cowboy_rest}.

rest_init(Req, [Module]) ->
    {ok, Req1, State} = wiggle_handler:initial_state(Req),
    {ok, Req1, State#state{module = Module}}.

rest_terminate(_Req, _State) ->
    ok.

service_available(Req, State) ->
    {wiggle_handler:service_available(), Req, State}.

options(Req, State = #state{module = M}) ->
    Methods = M:allowed_methods(State#state.version,
                                State#state.token,
                                State#state.path),
    wiggle_handler:options(Req, State,Methods).

content_types_provided(Req, State = #state{module = M}) ->
    CTFun = case erlang:function_exported(M, content_types_provided, 1) of
                true ->
                    fun M:content_types_provided/1;
                false ->
                    fun(_) -> wiggle_handler:provided() end
            end,
    {CTFun(State), Req, State}.

content_types_accepted(Req, State = #state{module = M}) ->
    CTFun = case erlang:function_exported(M, content_types_accepted, 1) of
                true ->
                    fun M:content_types_accepted/1;
                false ->
                    fun(_) -> wiggle_handler:accepted() end
            end,
    {CTFun(State), Req, State}.

allowed_methods(Req, State = #state{module = M}) ->
    {[<<"HEAD">>, <<"OPTIONS">> |
      M:allowed_methods(State#state.version,
                        State#state.token,
                        State#state.path)], Req, State}.

resource_exists(Req, State = #state{path = []}) ->
    {true, Req, State};

resource_exists(Req, State = #state{module = M}) ->
    case M:get(State) of
        not_found ->
            {false, Req, State};
        {ok, Obj} ->
            {true, Req, State#state{obj = Obj}}
    end.

-ifndef(old_hash).

generate_etag(Req, State = #state{obj = undefined}) ->
    {undefined, Req, State};
generate_etag(Req, State = #state{obj = Obj}) ->
    {{strong, base64:encode(crypto:hash(md5, term_to_binary(Obj)))}, Req, State}.

-else.

generate_etag(Req, State = #state{obj = undefined}) ->
    {undefined, Req, State};
generate_etag(Req, State = #state{obj = Obj}) ->
    {{strong, base64:encode(crypto:md5(term_to_binary(Obj)))}, Req, State}.

-endif.

is_authorized(Req, State = #state{method = <<"OPTIONS">>}) ->
    {true, Req, State};

is_authorized(Req, State = #state{method = <<"GET">>,
                                  module = wiggle_cloud_handler,
                                  path = [<<"connection">>]}) ->
    {true, Req, State};

is_authorized(Req, State = #state{method = <<"POST">>,
                                  module = wiggle_session_handler,
                                  path = []}) ->
    {true, Req, State};

is_authorized(Req, State = #state{token = undefined}) ->
    {{false, <<"x-snarl-token">>}, Req, State};

is_authorized(Req, State) ->
    {true, Req, State}.

forbidden(Req, State = #state{method = <<"OPTIONS">>}) ->
    {false, Req, State};

forbidden(Req, State = #state{method = <<"GET">>,
                              module = wiggle_cloud_handler,
                              path = [<<"connection">>]}) ->
    {false, Req, State};

forbidden(Req, State = #state{method = <<"POST">>,
                              module = wiggle_session_handler,
                              path = []}) ->
    {false, Req, State};

forbidden(Req, State = #state{token = undefined}) ->
    {true, Req, State};

forbidden(Req, State = #state{module = M}) ->
    case M:permission_required(State) of
        {error, needs_decode} ->
            {ok, Decoded, Req1} = wiggle_handler:decode(Req),
            forbidden(Req1, State#state{body = Decoded});
        undefined ->
            {true, Req, State};
        {ok, always} ->
            {false, Req, State};
        {multiple, Permissions} ->
            R = lists:foldl(fun(Permission, Acc) ->
                                    Acc andalso wiggle_handler:allowed(State, Permission)
                            end, false, Permissions),
            {not R, Req, State};
        {ok, Permission} ->
            {not wiggle_handler:allowed(State, Permission), Req, State}
    end.

%%--------------------------------------------------------------------
%% GET
%%--------------------------------------------------------------------

read(Req, State = #state{module = M}) ->
    case M:read(Req, State) of
        {{chunked, _StreamFun}, _Req, _State} = Reply ->
            Reply;
        {Reply, Req1, State1} ->
            Start = now(),
            {Data, Req2} = wiggle_handler:encode(Reply, Req1),
            ?MEx(?P(State), <<"encode">>, Start),
            {Data, Req2, State1#state{obj = Data}}
    end.

%%--------------------------------------------------------------------
%% write
%%--------------------------------------------------------------------

write(Req, State = #state{module = M, body = undefined}) ->
    RawFun = case erlang:function_exported(M, raw_body, 1) of
                 true ->
                     fun M:raw_body/1;
                 false ->
                     fun(_) -> false end
             end,
    case RawFun(State) of
        true ->
            lager:info("This is a raw request"),
            write2(Req, State);
        false ->
            {ok, Data, Req1} = wiggle_handler:decode(Req),
            write1(Req1, State#state{body = Data})
    end;

write(Req, State) ->
    write1(Req, State).

write1(Req, State = #state{body = Data}) ->
    case schema(State) of
        none ->
            write2(Req, State);
        Schema ->
            lager:info("[schema:~s] Validating.", [Schema]),
            case jesse:validate(Schema, Data) of
                {ok, _Data} ->
                    write2(Req, State);
                {error, E} ->
                    lager:error("[schema:~s] Malformated data: ~p",
                                [Schema, E]),
                    {false, Req, State}
            end
    end.

write2(Req, State = #state{module = M, body = Data}) ->
    case cowboy_req:method(Req) of
        {<<"POST">>, Req1} ->
            R = M:create(Req1, State, Data),
            wiggle_handler:clear_permissions(State),
            R;
        {<<"PUT">>, Req1} ->
            M:write(Req1, State, Data)
    end.

%%--------------------------------------------------------------------
%% DEETE
%%--------------------------------------------------------------------

delete_resource(Req, State = #state{module = M, body = undefined}) ->
    {ok, Data, Req1} = wiggle_handler:decode(Req),
    case M:delete(Req1, State#state{body = Data}) of
        {N, Req2, State1} when is_number(N) ->
            lager:info("Delete failed with ~p.", [N]),
            {ok, Req3} = cowboy_req:reply(N, Req2),
            {false, Req3, State1};
        {N, _, _} = R ->
            lager:info("Delete succeeded with ~p.", [N]),
            R
    end;

delete_resource(Req, State = #state{module = M}) ->
    case M:delete(Req, State) of
        {N, Req1, State1} when is_number(N) ->
            lager:info("Delete failed with ~p.", [N]),
            {ok, Req2} = cowboy_req:reply(N, Req1),
            {false, Req2, State1};
        {N, _, _} = R ->
            lager:info("Delete succeeded with ~p.", [N]),
            R
    end.

schema(State = #state{module = M}) ->
    case erlang:function_exported(M, schema, 1) of
        false ->
            none;
        true ->
            M:schema(State)
    end.
