%% Feel free to use, reuse and abuse the code in this file.

%% @doc Hello world handler.
-module(wiggle_scope_h).
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

allowed_methods(_, _Token, []) ->
    [<<"GET">>].

authorization_required(_State) ->
    false.

permission_required(_State) ->
    {ok, always}.

get(_State)  ->
    not_found.

%%--------------------------------------------------------------------
%% GET
%%--------------------------------------------------------------------

read(Req, State = #state{path = []}) ->
    {ok, Scopes} = ls_oauth:scope(),
    {to_json(Scopes), Req, State}.

%%--------------------------------------------------------------------
%% POST
%%--------------------------------------------------------------------

create(Req, State, _Decoded) ->
    {fase, Req, State}.

%%--------------------------------------------------------------------
%% PUT
%%--------------------------------------------------------------------

write(Req, State, _) ->
    {false, Req, State}.

%%--------------------------------------------------------------------
%% DEETE
%%--------------------------------------------------------------------

delete(Req, State) ->
    {false, Req, State}.

to_json(Scopes) ->
    [[{<<"default">>, Default},
      {<<"description">>, Desc},
      {<<"scope">>, Scope}]
     || #{scope := Scope, desc := Desc, default := Default} 
            <- Scopes].
