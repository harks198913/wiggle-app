-module(wiggle_vnc_h).

-behaviour(cowboy_websocket_handler).

-include("wiggle.hrl").

-export([init/3]).

-export([websocket_init/3,
         websocket_handle/3,
         websocket_info/3,
         websocket_terminate/3]).

-ignore_xref([init/3]).

-define(OPTS, [binary, {nodelay, true}, {packet, 0}]).
-define(SEC_HDR, <<"sec-websocket-protocol">>).

init({_Any, http}, _Req, _Opts) ->
    {upgrade, protocol, cowboy_websocket}.

e(Code, Req) ->
    e(Code, <<"">>, Req).

e(Code, Msg, Req) ->
    {ok, Req1} = cowboy_req:reply(Code, [], Msg, Req),
    {shutdown, Req1}.

websocket_init(_Any, Req, []) ->
    {ok, Ps, Req0} = cowboy_req:parse_header(?SEC_HDR, Req),
    case lists:member(<<"base64">>, Ps) of
        false ->
            e(400, Req0);
        _ ->
            Req1 = cowboy_req:set_resp_header(?SEC_HDR, <<"base64">>, Req0),
            {ID, Req2} = cowboy_req:binding(uuid, Req1),
            Req3 = wiggle_h:set_access_header(Req2),
            case wiggle_h:get_ws_token(Req3) of
                {_Error, Req4} ->
                    e(401, Req4);
                {ok, Token, SPerms, Req4} ->
                    check_permissions(ID, Token, SPerms, Req4)
            end
    end.

check_permissions(ID, Token, SPerms, Req) ->
    case wiggle_console_h:check_permissions(ID, Token, SPerms, Req) of
        {ok, VM, Req1} ->
            connect(VM, Req1);
        E ->
            E
    end.

connect(VM, Req) ->
    Info = ft_vm:info(VM),
    case {jsxd:get([<<"vnc">>, <<"host">>], Info),
          jsxd:get([<<"vnc">>, <<"port">>], Info)} of
        {{ok, Host}, {ok, Port}} when is_binary(Host),
                                      is_integer(Port)->
            case gen_tcp:connect(binary_to_list(Host), Port, ?OPTS) of
                {ok, Socket} ->
                    gen_tcp:controlling_process(Socket, self()),
                    Req1 = cowboy_req:compact(Req),
                    {ok, Req1, {Socket}, hibernate};
                E ->
                    e(500, io_lib:format("~p", [E]), Req)
            end;
        _ ->
            e(404, <<"could not find vnc">>, Req)
    end.

websocket_handle({text, Msg}, Req, {Socket} = State) ->
    gen_tcp:send(Socket, base64:decode(Msg)),
    {ok, Req, State};

websocket_handle(_Any, Req, State) ->
    {ok, Req, State}.

websocket_info({tcp, _Socket, Data}, Req, State) ->
    {reply, {text, base64:encode(Data)}, Req, State};

websocket_info(_Info, Req, State) ->
    {ok, Req, State, hibernate}.

websocket_terminate(_Reason, _Req, {Socket} = _State) ->
    Socket ! {ws, closed},
    gen_tcp:close(Socket),
    ok.
