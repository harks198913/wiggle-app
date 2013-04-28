%%% This file was automatically generated by snmpc_mib_to_hrl version 4.22.1
%%% Date: 28-Apr-2013::19:23:00
-ifndef('WIGGLE-MIB').
-define('WIGGLE-MIB', true).

%% Oids

-define(wiggle, [1,3,6,1,3,7]).
-define(name, [1,3,6,1,3,7,1]).
-define(name_instance, [1,3,6,1,3,7,1,0]).
-define(version, [1,3,6,1,3,7,2]).
-define(version_instance, [1,3,6,1,3,7,2,0]).

-define(vms, [1,3,6,1,3,7,3]).
-define(vmsP999, [1,3,6,1,3,7,3,1]).
-define(vmsP999_instance, [1,3,6,1,3,7,3,1,0]).
-define(vmsP99, [1,3,6,1,3,7,3,2]).
-define(vmsP99_instance, [1,3,6,1,3,7,3,2,0]).
-define(vmsP95, [1,3,6,1,3,7,3,3]).
-define(vmsP95_instance, [1,3,6,1,3,7,3,3,0]).
-define(vmsP75, [1,3,6,1,3,7,3,4]).
-define(vmsP75_instance, [1,3,6,1,3,7,3,4,0]).
-define(vmsP25, [1,3,6,1,3,7,3,5]).
-define(vmsP25_instance, [1,3,6,1,3,7,3,5,0]).
-define(vmsCount, [1,3,6,1,3,7,3,6]).
-define(vmsCount_instance, [1,3,6,1,3,7,3,6,0]).
-define(vmsMin, [1,3,6,1,3,7,3,7]).
-define(vmsMin_instance, [1,3,6,1,3,7,3,7,0]).
-define(vmsMedian, [1,3,6,1,3,7,3,8]).
-define(vmsMedian_instance, [1,3,6,1,3,7,3,8,0]).
-define(vmsMean, [1,3,6,1,3,7,3,9]).
-define(vmsMean_instance, [1,3,6,1,3,7,3,9,0]).
-define(vmsMax, [1,3,6,1,3,7,3,10]).
-define(vmsMax_instance, [1,3,6,1,3,7,3,10,0]).

-define(users, [1,3,6,1,3,7,4]).
-define(usersP999, [1,3,6,1,3,7,4,1]).
-define(usersP999_instance, [1,3,6,1,3,7,4,1,0]).
-define(usersP99, [1,3,6,1,3,7,4,2]).
-define(usersP99_instance, [1,3,6,1,3,7,4,2,0]).
-define(usersP95, [1,3,6,1,3,7,4,3]).
-define(usersP95_instance, [1,3,6,1,3,7,4,3,0]).
-define(usersP75, [1,3,6,1,3,7,4,4]).
-define(usersP75_instance, [1,3,6,1,3,7,4,4,0]).
-define(usersP25, [1,3,6,1,3,7,4,5]).
-define(usersP25_instance, [1,3,6,1,3,7,4,5,0]).
-define(usersCount, [1,3,6,1,3,7,4,6]).
-define(usersCount_instance, [1,3,6,1,3,7,4,6,0]).
-define(usersMin, [1,3,6,1,3,7,4,7]).
-define(usersMin_instance, [1,3,6,1,3,7,4,7,0]).
-define(usersMedian, [1,3,6,1,3,7,4,8]).
-define(usersMedian_instance, [1,3,6,1,3,7,4,8,0]).
-define(usersMean, [1,3,6,1,3,7,4,9]).
-define(usersMean_instance, [1,3,6,1,3,7,4,9,0]).
-define(usersMax, [1,3,6,1,3,7,4,10]).
-define(usersMax_instance, [1,3,6,1,3,7,4,10,0]).


%% Range values
-define(low_name, 0).
-define(high_name, 255).
-define(low_version, 0).
-define(high_version, 255).


%% Default values
-define(default_name, []).
-define(default_version, []).
-define(default_vmsP999, 0).
-define(default_vmsP99, 0).
-define(default_vmsP95, 0).
-define(default_vmsP75, 0).
-define(default_vmsP25, 0).
-define(default_vmsCount, 0).
-define(default_vmsMin, 0).
-define(default_vmsMedian, 0).
-define(default_vmsMean, 0).
-define(default_vmsMax, 0).
-define(default_usersP999, 0).
-define(default_usersP99, 0).
-define(default_usersP95, 0).
-define(default_usersP75, 0).
-define(default_usersP25, 0).
-define(default_usersCount, 0).
-define(default_usersMin, 0).
-define(default_usersMedian, 0).
-define(default_usersMean, 0).
-define(default_usersMax, 0).

-endif.
