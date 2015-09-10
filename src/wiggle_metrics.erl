-module(wiggle_metrics).

-export([get/2, short_id/1, mb/1, der/1]).

short_id(<<ID:30/binary, _/binary>>) ->
    ID;
short_id(ID) when is_binary(ID) ->
    ID.

mb(E) ->
    {f, divide, [E, 1048576]}.

der(E) ->
    {f, derivate, [E]}.

get(Elems, QS) ->
    QS1 = lists:sort(QS),
    Elems1 = translate(Elems),
    {ok, Q} = case lists:keytake(<<"aggr">>, 1, QS1) of
                  false ->
                      perf1(Elems1, QS1);
                  {value, {<<"aggr">>, Res}, QS2} ->
                      case valid_time(Res) of
                          true ->
                              Elems2 = apply_aggr("avg", Res, Elems1),
                              perf1(Elems2, QS2);
                          false ->
                              {error, bad_resolution}
                      end
              end,
    {ok, _T0, Res1} = dqe:run(Q),
    [[{<<"n">>, Name},
      {<<"r">>, Resolution},
      {<<"v">>, mmath_bin:to_list(Data)}]
     || {Name, Data, Resolution} <- Res1].


perf1(Elems, [{<<"last">>, Last}]) ->
    case valid_time(Last) of
        true ->
            {ok, apply_query(Elems, ["LAST ", Last])};
        false ->
            {error, bad_last}
    end;


perf1(Elems, [{<<"after">>, After}, {<<"for">>, For}]) ->
    case valid_pit(After) andalso valid_time(For) of
        true ->
            {ok, apply_query(Elems, ["AFTER ", After, " FOR ", For])};
        false ->
            {error, bad_after}
    end;

perf1(Elems, [{<<"before">>, Before}, {<<"for">>, For}]) ->
    case valid_pit(Before) andalso valid_time(For) of
        true ->
            {ok, apply_query(Elems, ["BEFORE ", Before, " FOR ", For])};
        false ->
            {error, bad_before}
    end;

perf1(Elems, []) ->
    {ok, apply_query(Elems, "LAST 1m")};

perf1(_Elems, _) ->
    {error, bad_qs}.


apply_aggr(Aggr, Res, Elements) ->
    [{[Aggr, $(, Qry, ", ", Res, $)], Alias} ||
        {Qry, Alias} <- Elements].

apply_query(Elements, Range) ->
    Elements1 = [[Qry, " AS '", Alias, "'"] || {Qry, Alias} <- Elements],
    iolist_to_binary(["SELECT ", string:join(Elements1, ", "), " ", Range]).

valid_time(_Time) ->
    true. %% TODO!

valid_pit(_PIT) ->
    true. %% TODO

translate({m, Bucket, L}) ->
    L1 = [string(E) || E <- L],
    L2 = [case E of
              "*" ->
                  "*";
              _ ->
                  [$', E, $']
          end || E <- L1],
    [string:join(L2, "."), " BUCKET '", string(Bucket), "'"];
translate({f, F, Args}) ->
    [string(F), $(, string:join([translate(A) || A <- Args], ", "), $)];

translate(L) when is_list(L) ->
    [{translate(Body), string(Alias)} || {Alias, Body} <- L];
translate(Any) ->
    string(Any).


string(A) when is_atom(A) ->
    atom_to_list(A);
string(I) when is_integer(I) ->
    integer_to_list(I);
string(B) when is_binary(B) ->
    B;
string(L) when is_list(L) ->
    L.
