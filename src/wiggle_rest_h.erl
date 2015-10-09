-module(wiggle_rest_h).

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

-export([read_raw/2,
         write_raw/2]).

-export([read_json/2,
         write_json/2]).

-export([read_msgpack/2,
         write_msgpack/2]).

-ignore_xref([
              read_raw/2,
              write_raw/2,
              read_json/2,
              write_json/2,
              read_msgpack/2,
              write_msgpack/2,
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
    not_found | {ok, term()}.

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



-callback service_available(handler_state()) ->
    true | false.

-callback authorization_required(handler_state()) ->
    true | false.

-callback content_types_provided(handler_state()) ->
    [{{binary(), binary(), [term()] | '*'}, atom()}].

-callback content_types_accepted(handler_state()) ->
    [{{binary(), binary(), [term()] | '*'}, atom()}].



-callback schema(handler_state()) ->
    none | atom().


-optional_callbacks([service_available/1, schema/1, authorization_required/1,
                     content_types_provided/1, content_types_accepted/1]).

init(_Transport, _Req, _) ->
    {upgrade, protocol, cowboy_rest}.

rest_init(Req, [Module]) ->
    {ok, Req1, State} = wiggle_h:initial_state(Req),
    {ok, Req1, State#state{module = Module}}.

rest_terminate(_Req, _State) ->
    ok.

service_available(Req, State = #state{module = M}) ->
    AFun = case erlang:function_exported(M, service_available, 1) of
               true ->
                   fun M:service_available/1;
               false ->
                   fun(_) -> wiggle_h:service_available() end
           end,
    {AFun(State), Req, State}.

options(Req, State = #state{module = M}) ->
    Methods = M:allowed_methods(State#state.version,
                                State#state.token,
                                State#state.path),
    wiggle_h:options(Req, State,Methods).


content_types_provided(Req, State = #state{module = M}) ->
    CTFun = case erlang:function_exported(M, content_types_provided, 1) of
                true ->
                    fun M:content_types_provided/1;
                false ->
                    fun(_) -> wiggle_h:provided() end
            end,
    {CTFun(State), Req, State}.

content_types_accepted(Req, State = #state{module = M}) ->
    CTFun = case erlang:function_exported(M, content_types_accepted, 1) of
                true ->
                    fun M:content_types_accepted/1;
                false ->
                    fun(_) -> wiggle_h:accepted() end
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

generate_etag(Req, State = #state{obj = undefined}) ->
    {undefined, Req, State};
generate_etag(Req, State = #state{obj = Obj}) ->
    {{strong, base64:encode(crypto:hash(md5, term_to_binary(Obj)))}, Req, State}.

is_authorized(Req, State = #state{method = <<"OPTIONS">>}) ->
    {true, Req, State};

is_authorized(Req, State = #state{token = undefined, module = M}) ->
    F = case erlang:function_exported(M, authorization_required, 1) of
            true ->
                fun M:authorization_required/1;
            false ->
                fun(_) -> true end
        end,
    case F(State) of
        true ->
            {{false, <<"authorization">>}, Req, State};
        false ->
            {true, Req, State}
    end;

is_authorized(Req, State) ->
    {true, Req, State}.

forbidden(Req, State = #state{method = <<"OPTIONS">>}) ->
    {false, Req, State};

forbidden(Req, State = #state{token = undefined, module = M}) ->
    F = case erlang:function_exported(M, authorization_required, 1) of
            true ->
                fun M:authorization_required/1;
            false ->
                fun(_) -> true end
        end,
    {F(State), Req, State};

forbidden(Req, State = #state{module = M}) ->
    case M:permission_required(State) of
        {error, needs_decode} ->
            {ok, Decoded, Req1} = wiggle_h:decode(Req),
            forbidden(Req1, State#state{body = Decoded});
        undefined ->
            {true, Req, State};
        {ok, always} ->
            {false, Req, State};
        {multiple, Permissions} ->
            R = lists:foldl(fun(_, false) ->
                                    %% We can just keep returning false once we
                                    %% got the first false given false and *
                                    %% will always return false.
                                    false;
                               (Permission, Acc) ->
                                    Acc andalso wiggle_h:allowed(State, Permission)
                            end, true, Permissions),
            {not R, Req, State};
        {ok, Permission} ->
            {not wiggle_h:allowed(State, Permission), Req, State}
    end.

%%--------------------------------------------------------------------
%% GET
%%--------------------------------------------------------------------


read_raw(Req, State) ->
    read(Req, raw, State).

read_json(Req, State) ->
    read(Req, json, State).

read_msgpack(Req, State) ->
    read(Req, msgpack, State).

read(Req, raw, State = #state{module = M}) ->
    case M:read(Req, State) of
        {halt, _Req, _State} = Reply ->
            Reply;
        {{chunked, _StreamFun}, _Req, _State} = Reply ->
            Reply;
        {Data, Req1, State1} ->
            Start = erlang:system_time(micro_seconds),
            ?MEx(?P(State), <<"encode">>, Start),
            {Data, Req1, State1#state{obj = Data}}
    end;

read(Req, MediaType, State = #state{module = M}) ->
    case M:read(Req, State) of
        {halt, _Req, _State} = Reply ->
            Reply;
        {{chunked, _StreamFun}, _Req, _State} = Reply ->
            Reply;
        {Reply, Req1, State1} ->
            Start = erlang:system_time(micro_seconds),
            {Data, Req2} = wiggle_h:encode(Reply, MediaType, Req1),
            ?MEx(?P(State), <<"encode">>, Start),
            {Data, Req2, State1#state{obj = Data}}
    end.

%%--------------------------------------------------------------------
%% write
%%--------------------------------------------------------------------

write_raw(Req, State) ->
    write(Req, raw, State).

write_json(Req, State) ->
    write(Req, json, State).

write_msgpack(Req, State) ->
    write(Req, msgpack, State).

write(Req, raw, State = #state{ body = undefined}) ->
    write2(Req, State);

write(Req, ContentType, State = #state{body = undefined}) ->
    {ok, Data, Req1} = wiggle_h:decode(Req, ContentType),
    write1(Req1, State#state{body = Data});

write(Req, _ContentType, State) ->
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
            wiggle_h:clear_permissions(State),
            R;
        {<<"PUT">>, Req1} ->
            M:write(Req1, State, Data)
    end.

%%--------------------------------------------------------------------
%% DEETE
%%--------------------------------------------------------------------

delete_resource(Req, State = #state{module = M, body = undefined}) ->
    {ok, Data, Req1} = wiggle_h:decode(Req),
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
