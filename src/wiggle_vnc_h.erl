-module(wiggle_vnc_h).

-behaviour(cowboy_websocket_handler).

-include("wiggle.hrl").

-export([init/3]).

-export([websocket_init/3,
         websocket_handle/3,
         websocket_info/3,
         websocket_terminate/3]).

-ignore_xref([init/3]).

init({_Any, http}, _Req, _Opts) ->
    {upgrade, protocol, cowboy_websocket}.

e(Code, Req) ->
    e(Code, <<"">>, Req).

e(Code, Msg, Req) ->
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
               {ok, List, ReqR} ->
                   case lists:member(<<"base64">>, List) of
                       true ->
                           cowboy_req:set_resp_header(<<"sec-websocket-protocol">>, <<"base64">>, ReqR);
                       _ ->
                           {stop, ReqR}
                   end
           end,
    case Req0 of
        {stop, ReqR1} ->
            e(400, ReqR1);
        _ ->
            {ID, Req1} = cowboy_req:binding(uuid, Req0),
            Req2 = wiggle_h:set_access_header(Req1),

            case get_token(Req2) of
                {_Error, Req3} ->
                    e(401, Req3);
                {ok, Token, SPerms, Req3} ->
                    Permission = [<<"vms">>, ID, <<"console">>],
                    case libsnarlmatch:test_perms(Permission, SPerms)
                        andalso libsnarl:allowed(Token, Permission) of
                        true ->
                            case ls_vm:get(ID) of
                                {ok, VM} ->
                                    Info = ft_vm:info(VM),
                                    case {jsxd:get([<<"vnc">>, <<"host">>], Info),
                                          jsxd:get([<<"vnc">>, <<"port">>], Info)} of
                                        {{ok, Host}, {ok, Port}} when is_binary(Host),
                                                                      is_integer(Port)->
                                            case gen_tcp:connect(binary_to_list(Host), Port,
                                                                 [binary,{nodelay, true}, {packet, 0}]) of
                                                {ok, Socket} ->
                                                    gen_tcp:controlling_process(Socket, self()),
                                                    Req4 = cowboy_req:compact(Req3),
                                                    {ok, Req4, {Socket}, hibernate};
                                                E ->
                                                    e(500, list_to_binary(io_lib:format("~p", [E])), Req)
                                            end;
                                        _ ->
                                            e(404, <<"could not find vnc">>, Req3)
                                    end;
                                E ->
                                    e(404, list_to_binary(io_lib:format("~p", [E])), Req3)
                            end;
                        false ->
                            e(401, Req3)
                    end
            end
    end.

websocket_handle({text, Msg}, Req, {Socket} = State) ->
    gen_tcp:send(Socket, base64:decode(Msg)),
    {ok, Req, State};

websocket_handle(_Any, Req, State) ->
    {ok, Req, State}.

websocket_info({tcp,_Socket,Data}, Req, State) ->
    {reply, {text, base64:encode(Data)}, Req, State};

websocket_info(_Info, Req, State) ->
    {ok, Req, State, hibernate}.

websocket_terminate(_Reason, _Req, {Socket} = _State) ->
    Socket ! {ws, closed},
    gen_tcp:close(Socket),
    ok.
