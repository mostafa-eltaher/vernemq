%% Copyright 2014 Erlio GmbH Basel Switzerland (http://erl.io)
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

-module(vmq_psk).
%-behaviour(auth_on_register_hook).
-behaviour(on_config_change_hook).

-export([start/0,
         stop/0,
         init/0,
         user_lookup/1,
         load_from_file/1,
         load_from_list/1]).
-export([change_config/1,
         ssl_on_psk_user_lookup/2]).

-define(TABLE, ?MODULE).
-define(SALT_LEN, 12).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Plugin Callbacks
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
start() ->
    {ok, _} = application:ensure_all_started(vmq_psk),
    vmq_psk_cli:register(),
    ok.

stop() ->
    application:stop(vmq_psk).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Hooks
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
change_config(Configs) ->
    case lists:keyfind(vmq_psk, 1, Configs) of
        false ->
            ok;
        _ ->
            vmq_psk_reloader:change_config_now()
    end.

ssl_on_psk_user_lookup(PSKIdentity, _Userstate) ->
    user_lookup(PSKIdentity).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Internal
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
init() ->
    case lists:member(?TABLE, ets:all()) of
        true ->
            ok;
        false ->
            ets:new(?TABLE, [public, named_table, {read_concurrency, true}])
    end,
    ok.

load_from_file(File) ->
    case file:open(File, [read, binary]) of
        {ok, Fd} ->
            age_entries(),
            F = fun(FF, read) -> {FF, rl(Fd)};
                   (_, close) -> file:close(Fd)
                end,
            parse_passwd_line(F(F,read)),
            del_aged_entries();
        {error, _Reason} ->
            ok
    end.

load_from_list(List) ->
    age_entries(),
    put(vmq_psk_list, List),
    F = fun(FF, read) ->
                case get(vmq_psk_list) of
                    [I|Rest] ->
                        put(vmq_psk_list, Rest),
                        {FF, I};
                    [] ->
                        {FF, eof}
                end;
           (_, close) ->
                put(vmq_psk_list, undefined),
                ok
        end,
    parse_passwd_line(F(F, read)),
    del_aged_entries().


user_lookup(undefined) ->
    next;
user_lookup(PSKIdentity) ->
    case ets:lookup(?TABLE, PSKIdentity) of
        [{_, EncPassword, _}] -> 
            Psk = base64:decode(EncPassword),
            case is_binary(Psk) of
                true -> {ok, Psk};
                false -> {error, invalid_credentials}
            end;
        [] ->
            next
    end.

parse_passwd_line({F, eof}) ->
    F(F,close),
    ok;
parse_passwd_line({F, <<"\n">>}) ->
    parse_passwd_line(F(F,read));
parse_passwd_line({F, Line}) ->
    [User, Rest] = re:split(Line, ":"),
    %[<<>>, _, EncPasswd] = binary:split(Rest, <<"$">>, [global]),
    %L = byte_size(EncPasswd) -1,
    %EncPasswdNew =
    %case EncPasswd of
    %    <<E:L/binary, "\n">> -> E;
    %    _ -> EncPasswd
    %end,
    Item = {User, Rest, 1},
    ets:insert(?TABLE, Item),
    parse_passwd_line(F(F,read)).

age_entries() ->
    iterate(fun(K) -> ets:update_element(?TABLE, K, {3,2}) end).

del_aged_entries() ->
    ets:match_delete(?TABLE, {'_', '_', 2}),
    ok.

iterate(Fun) ->
    iterate(Fun, ets:first(?TABLE)).
iterate(_, '$end_of_table') -> ok;
iterate(Fun, K) ->
    Fun(K),
    iterate(Fun, ets:next(?TABLE, K)).


rl({ok, Data}) -> Data;
rl({error, Reason}) -> exit(Reason);
rl(eof) -> eof;
rl(Fd) ->
    rl(file:read_line(Fd)).

% ensure_binary(L) when is_list(L) -> list_to_binary(L);
% ensure_binary(B) when is_binary(B) -> B.


% hash(Password) ->
%     hash(Password, crypto:strong_rand_bytes(?SALT_LEN)).

% hash(Password, Salt) ->
%     Ctx1 = crypto:hash_init(sha512),
%     Ctx2 = crypto:hash_update(Ctx1, Password),
%     Ctx3 = crypto:hash_update(Ctx2, Salt),
%     Digest = crypto:hash_final(Ctx3),
%     base64:encode(Digest).
