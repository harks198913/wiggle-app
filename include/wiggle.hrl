-record(state, {
          %% The callback module responsible for the REST interactions
          module :: module(),
          %% The path of the reqest
          path :: wiggle_h:path(),
          %% The method of the request, as binary and atom
          method :: binary(),
          method_a :: wiggle_h:method(),
          %% The API version
          version :: binary(),
          version_i :: pos_integer(),
          %% The token (either {token, ...} or user uuid)
          token,
          %% The object the reuqest is asking for (from the DB)
          obj,
          %% Body of the request (from the client)
          body,
          %% When the request was started.
          start,
          %% The whole path as a binary
          path_bin :: binary(),
          %% The ETAG when generated
          etag,
          %% The bearer token when OAuth is used
          bearer,
          %% A cached set of permissons
          cached_perms,
          encoding,
          %% The permissions granted by the OAuth2 scope.
          %% If we don't have a scope aka don't use oatuh2 we always allow
          %% everything from a scope pov.
          scope_perms = [[<<"...">>]] :: [wiggle_h:permission()],
          %% Te full list header
          full_list = false :: boolean(),
          %% The full list fields
          full_list_fields = [] :: [binary()]
         }).

-define(P(State), State#state.path_bin).
-define(MEx(Path, Service, Start), io_lib:format("~p~p", [Path, Start])).
%%-define(MEx(Path, Service, Start),
%%        statman_histogram:record_value({Path, {ext, Service}}, Start - erlang:system_time(micro_seconds))).
-define(MSnarl(Path, Start), ?MEx(Path, <<"snarl">>, Start)).
-define(MSniffle(Path, Start), ?MEx(Path, <<"sniffle">>, Start)).
-define(MHowl(Path, Start), ?MEx(Path, <<"howl">>, Start)).
-define(M(Path, Start), ok).
-define(UUID(N), <<N:36/binary>>).

%-define(M(Path, Start), statman_histogram:record_value({Path, total}, Start)).
%-define(M(Path, Start), statman_histogram:record_value({Path, total}, Start)).

-define(V2, <<"2">>).

-define(V, ?V2).

