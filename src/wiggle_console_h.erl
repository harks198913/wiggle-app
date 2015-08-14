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
    {#state{token = Token, scope_perms = SPerms}, Req3} =
        wiggle_h:get_token(#state{}, Req2),
    case Token of
        undefined ->
            e(401, Req3);
        Token ->
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
            end
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
