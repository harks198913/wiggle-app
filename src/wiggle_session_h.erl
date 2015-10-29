%% Feel free to use, reuse and abuse the code in this file.

%% @doc Hello world handler.
-module(wiggle_session_h).
-include("wiggle.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([allowed_methods/3,
         permission_required/1,
         authorization_required/1,
         get/1,
         create/3,
         read/2,
         write/3,
         delete/2]).

-behaviour(wiggle_rest_h).

allowed_methods(?V2, _Token, []) ->
    [<<"GET">>];

allowed_methods(?V2, _Token, [<<"one_time_token">>]) ->
    [<<"GET">>];
allowed_methods(?V2, _Token, [_Session]) ->
    [<<"DELETE">>].

get(#state{version = ?V2, path = [<<"one_time_token">>],
           bearer = Bearer}) when is_binary(Bearer) ->
    {ok, {oauth2_token:generate('x-snarl-one-time-token'), Bearer}};

get(_State) ->
    not_found.

authorization_required(#state{method = <<"POST">>}) ->
    false;

authorization_required(_) ->
    true.

permission_required(_State) ->
    {ok, always}.

%%--------------------------------------------------------------------
%% GET
%%--------------------------------------------------------------------

read(Req, State = #state{path = [<<"one_time_token">>],
                         obj = {OTT, Bearer}, version = ?V2}) ->
    Start = erlang:system_time(micro_seconds),
    {ok, OTT} = ls_token:add(OTT, 30, Bearer),
    ?MSnarl(?P(State), Start),
    {[{<<"expiery">>, 30}, {<<"token">>, OTT}], Req, State};

read(Req, State = #state{path = [], token = Token, version = ?V2}) ->
    {ok, Obj} = ls_user:get(Token),
    {wiggle_user_h:to_json(Obj), Req, State}.

%%--------------------------------------------------------------------
%% PUT
%%--------------------------------------------------------------------

create(Req, State, _) ->
    {halt, Req, State}.

write(Req, State, _) ->
    {false, Req, State}.

%%--------------------------------------------------------------------
%% DEETE
%%--------------------------------------------------------------------

delete(Req, State = #state{path = [Session]}) ->
    ls_token:delete(Session),
    {true, Req, State}.
