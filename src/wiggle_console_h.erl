-module(wiggle_console_h).

-behaviour(cowboy_websocket_handler).

-include("wiggle.hrl").

-export([init/3]).

-export([websocket_init/3,
         websocket_handle/3,
         websocket_info/3,
         websocket_terminate/3]).

-ignore_xref([init/3]).

init({_Any, http}, _Req, []) ->
    {upgrade, protocol, cowboy_websocket}.


e(Code, Req) ->
    e(Code, <<"">>, Req).

e(Code, Msg, Args, Req) ->
    e(Code, bf(Msg, Args), Req).

e(Code, Msg, Req) ->
    lager:error("[console:~p] Error: ~s", [Code, Msg]),
    {ok, Req1} = cowboy_req:reply(Code, [], Msg, Req),
    {shutdown, Req1}.


%% Fuck you dialyzer, it refuses to accept that get_token can
%% return stuff other then no_token ...
-dialyzer({nowarn_function, [get_token/2]}).
-spec get_token(Req) ->
                       {ok, binary(), [[binary()]], Req} |
                       {denied, Req} |
                       {no_token, Req}
                           when Req :: cowboy_req:req().
get_token(Req) ->
    case cowboy_req:qs_val(<<"fifo_ott">>, Req) of
        {OTT, Req1} when is_binary(OTT) ->
            case ls_token:get(OTT) of
                {ok, Bearer} ->
                    ls_token:delete(OTT),
                    case ls_oauth:verify_access_token(Bearer) of
                        {ok, Context} ->
                            case {proplists:get_value(<<"resource_owner">>, Context),
                                  proplists:get_value(<<"scope">>, Context)} of
                                {undefined, _} ->
                                    {denied, Req1};
                                {UUID, Scope} ->
                                    {ok, Scopes} = ls_oauth:scope(Scope),
                                    SPerms = cowboy_oauth:scope_perms(Scopes, []),
                                    {ok, UUID, SPerms, Req1}
                            end;
                        _ ->
                            {denied, Req1}
                    end;
                _ ->
                    {denied, Req1}
            end;
        {undefined, Req1} ->
            {no_token, Req1}
    end.

websocket_init(_Any, Req, []) ->
    Req0 = case cowboy_req:parse_header(<<"sec-websocket-protocol">>, Req) of
               {ok, undefined, ReqR} ->
                   ReqR;
               {ok, [], ReqR} ->
                   ReqR;
               {ok, [P |_], ReqR} ->
                   cowboy_req:set_resp_header(<<"sec-websocket-protocol">>, P, ReqR)
           end,
    {ID, Req1} = cowboy_req:binding(uuid, Req0),
    Req2 = wiggle_h:set_access_header(Req1),

    case get_token(Req2) of
        {ok, Token, SPerms, Req3} ->
            Permission = [<<"vms">>, ID, <<"console">>],
            case libsnarlmatch:test_perms(Permission, SPerms)
                andalso libsnarl:allowed(Token, Permission) of
                true ->
                    case ls_vm:get(ID) of
                        {ok, VM} ->
                            HID = ft_vm:hypervisor(VM),
                            case ls_hypervisor:get(HID) of
                                {ok, H} ->
                                    {Host, Port} = ft_hypervisor:endpoint(H),
                                    {ok, Console} = libchunter:console_open(Host, Port, ID, self()),
                                    {ok, Req3, {Console}};
                                HVErr ->
                                    e(505, "could not find hypervisor ~s ~p",
                                      [HID, HVErr], Req3)
                            end;
                        E ->
                            e(505, "~p", [E], Req3)
                    end;
                false ->
                    e(401, Req3)
            end;
        {_Error, Req3} ->
            e(401, Req3)
    end.

bf(F, A) ->
    list_to_binary(io_lib:format(F, A)).

websocket_handle({text, Msg}, Req, {Console} = State) ->
    libchunter_console_server:send(Console, Msg),
    {ok, Req, State};

websocket_handle(_Any, Req, State) ->
    {ok, Req, State}.

websocket_info({data, Data}, Req, State) ->
    {reply, {text, Data}, Req, State};

websocket_info(_Info, Req, State) ->
    {ok, Req, State, hibernate}.

websocket_terminate(_Reason, _Req, {Console} = _State) ->
    libchunter_console_server:close(Console),
    ok.
