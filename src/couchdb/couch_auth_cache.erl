% Licensed under the Apache License, Version 2.0 (the "License"); you may not
% use this file except in compliance with the License. You may obtain a copy of
% the License at
%
%   http://www.apache.org/licenses/LICENSE-2.0
%
% Unless required by applicable law or agreed to in writing, software
% distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
% WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
% License for the specific language governing permissions and limitations under
% the License.

-module(couch_auth_cache).
-behaviour(gen_server).

% public API
-export([get_user_creds/1, add_oauth_creds/2]).

% gen_server API
-export([start_link/0, init/1, handle_call/3, handle_info/2, handle_cast/2]).
-export([code_change/3, terminate/2]).

-include("couch_db.hrl").
-include("couch_js_functions.hrl").

-define(STATE, auth_state_ets).
-define(BY_USER, auth_by_user_ets).
-define(BY_ATIME, auth_by_atime_ets).

% maps oauth pair ({consumer_key, token}) to oauth credentials and last
% access time
-define(OAUTH_TO_CREDS, oauth_pair_to_user_creds_ets).
% maps a username into a list of oauth pairs (that are defined by his user doc)
-define(USER_TO_OAUTH_PAIRS, user_doc_id_to_oauth_pairs_ets).
% maps access times to oauth pairs and respective users
-define(BY_ATIME_OAUTH, oauth_pair_to_atime_ets).

-record(state, {
    max_cache_size = 0,
    cache_size = 0,
    max_oauth_pairs = 0,
    num_oauth_pairs = 0,
    db_notifier = nil
}).


-type oauth_pair() :: {ConsumerKey :: string(), Token :: string()}.
-type roles() :: [binary()].
-spec get_user_creds(UserName::string() | binary() | oauth_pair()) ->
    Credentials::list() |
    {UserName::binary(), UserRoles::roles(), DelegationDb::binary(),
        ConsumerSecret::string(), TokenSecret::string()} |
    nil.

get_user_creds({_ConsumerKey, _Token} = OAuthPair) ->
    get_from_cache(OAuthPair);

get_user_creds(UserName) when is_list(UserName) ->
    get_user_creds(?l2b(UserName));

get_user_creds(UserName) ->
    UserCreds = case couch_config:get("admins", ?b2l(UserName)) of
    "-hashed-" ++ HashedPwdAndSalt ->
        % the name is an admin, now check to see if there is a user doc
        % which has a matching name, salt, and password_sha
        [HashedPwd, Salt] = string:tokens(HashedPwdAndSalt, ","),
        case get_from_cache(UserName) of
        nil ->
            [{<<"roles">>, [<<"_admin">>]},
                {<<"salt">>, ?l2b(Salt)},
                {<<"password_sha">>, ?l2b(HashedPwd)}];
        UserProps when is_list(UserProps) ->
            DocRoles = couch_util:get_value(<<"roles">>, UserProps),
            [{<<"roles">>, [<<"_admin">> | DocRoles]},
                {<<"salt">>, ?l2b(Salt)},
                {<<"password_sha">>, ?l2b(HashedPwd)}]
        end;
    _Else ->
        get_from_cache(UserName)
    end,
    validate_user_creds(UserCreds).


get_from_cache({_ConsumerKey, _Token} = OAuthPair) ->
    exec_if_auth_db(
        fun(_AuthDb) ->
            maybe_refresh_cache(),
            case ets:lookup(?OAUTH_TO_CREDS, OAuthPair) of
            [] ->
                couch_stats_collector:increment({couchdb, auth_cache_misses}),
                nil;
            [{OAuthPair, {Credentials, _ATime}}] ->
                couch_stats_collector:increment({couchdb, auth_cache_hits}),
                gen_server:cast(?MODULE, {cache_hit, OAuthPair}),
                Credentials
            end
        end,
        nil
    );

get_from_cache(UserName) ->
    exec_if_auth_db(
        fun(_AuthDb) ->
            maybe_refresh_cache(),
            case ets:lookup(?BY_USER, UserName) of
            [] ->
                gen_server:call(?MODULE, {fetch, UserName}, infinity);
            [{UserName, {Credentials, _ATime}}] ->
                couch_stats_collector:increment({couchdb, auth_cache_hits}),
                gen_server:cast(?MODULE, {cache_hit, UserName}),
                Credentials
            end
        end,
        nil
    ).


add_oauth_creds(OAuthPair, Credentials) ->
    ok = gen_server:cast(?MODULE, {add_oauth_creds, OAuthPair, Credentials}).


validate_user_creds(nil) ->
    nil;
validate_user_creds(UserCreds) ->
    case couch_util:get_value(<<"_conflicts">>, UserCreds) of
    undefined ->
        ok;
    _ConflictList ->
        throw({unauthorized,
            <<"User document conflicts must be resolved before the document",
              " is used for authentication purposes.">>
        })
    end,
    UserCreds.


start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).


init(_) ->
    ?STATE = ets:new(?STATE, [set, protected, named_table]),
    ?BY_USER = ets:new(?BY_USER, [set, protected, named_table]),
    ?BY_ATIME = ets:new(?BY_ATIME, [ordered_set, private, named_table]),
    ?OAUTH_TO_CREDS = ets:new(?OAUTH_TO_CREDS, [set, protected, named_table]),
    ?USER_TO_OAUTH_PAIRS = ets:new(
        ?USER_TO_OAUTH_PAIRS, [bag, private, named_table]),
    ?BY_ATIME_OAUTH = ets:new(
        ?BY_ATIME_OAUTH, [ordered_set, private, named_table]),
    AuthDbName = couch_config:get("couch_httpd_auth", "authentication_db"),
    true = ets:insert(?STATE, {auth_db_name, ?l2b(AuthDbName)}),
    true = ets:insert(?STATE, {auth_db, open_auth_db()}),
    process_flag(trap_exit, true),
    ok = couch_config:register(
        fun("couch_httpd_auth", "auth_cache_size", SizeList) ->
            Size = list_to_integer(SizeList),
            ok = gen_server:call(?MODULE, {new_max_cache_size, Size}, infinity);
        ("couch_httpd_auth", "oauth_cache_size", SizeList) ->
            Sz = list_to_integer(SizeList),
            ok = gen_server:call(?MODULE, {new_max_oauth_pairs, Sz}, infinity);
        ("couch_httpd_auth", "authentication_db", DbName) ->
            ok = gen_server:call(?MODULE, {new_auth_db, ?l2b(DbName)}, infinity)
        end
    ),
    {ok, Notifier} = couch_db_update_notifier:start_link(fun handle_db_event/1),
    State = #state{
        db_notifier = Notifier,
        max_cache_size = list_to_integer(
            couch_config:get("couch_httpd_auth", "auth_cache_size", "50")
        ),
        max_oauth_pairs = list_to_integer(
            couch_config:get("couch_httpd_auth", "oauth_cache_size", "1000")
        )
    },
    {ok, State}.


handle_db_event({Event, DbName}) ->
    [{auth_db_name, AuthDbName}] = ets:lookup(?STATE, auth_db_name),
    case DbName =:= AuthDbName of
    true ->
        case Event of
        deleted -> gen_server:call(?MODULE, auth_db_deleted, infinity);
        created -> gen_server:call(?MODULE, auth_db_created, infinity);
        _Else   -> ok
        end;
    false ->
        ok
    end.


handle_call({new_auth_db, AuthDbName}, _From, State) ->
    NewState = clear_cache(State),
    true = ets:insert(?STATE, {auth_db_name, AuthDbName}),
    true = ets:insert(?STATE, {auth_db, open_auth_db()}),
    {reply, ok, NewState};

handle_call(auth_db_deleted, _From, State) ->
    NewState = clear_cache(State),
    true = ets:insert(?STATE, {auth_db, nil}),
    {reply, ok, NewState};

handle_call(auth_db_created, _From, State) ->
    NewState = clear_cache(State),
    true = ets:insert(?STATE, {auth_db, open_auth_db()}),
    {reply, ok, NewState};

handle_call({new_max_cache_size, NewSize},
        _From, #state{cache_size = Size} = State) when NewSize >= Size ->
    {reply, ok, State#state{max_cache_size = NewSize}};

handle_call({new_max_cache_size, NewSize}, _From, State) ->
    free_mru_cache_entries(State#state.cache_size - NewSize),
    {reply, ok, State#state{max_cache_size = NewSize, cache_size = NewSize}};

handle_call({new_max_oauth_pairs, NewSize}, _From,
        #state{num_oauth_pairs = Size} = State) when NewSize >= Size ->
    {reply, ok, State#state{max_oauth_pairs = NewSize}};

handle_call({new_max_oauth_pairs, NewSize}, _From, State) ->
    free_oauth_mru_cache_entries(State#state.num_oauth_pairs - NewSize),
    NewState = State#state{
        max_oauth_pairs = NewSize,
        num_oauth_pairs = NewSize
    },
    {reply, ok, NewState};

handle_call({fetch, UserName}, _From, State) ->
    {Credentials, NewState} = case ets:lookup(?BY_USER, UserName) of
    [{UserName, {Creds, ATime}}] ->
        couch_stats_collector:increment({couchdb, auth_cache_hits}),
        cache_hit(UserName, Creds, ATime),
        {Creds, State};
    [] ->
        couch_stats_collector:increment({couchdb, auth_cache_misses}),
        Creds = get_user_props_from_db(UserName),
        State1 = add_cache_entry(UserName, Creds, erlang:now(), State),
        {Creds, State1}
    end,
    {reply, Credentials, NewState};

handle_call(refresh, _From, State) ->
    exec_if_auth_db(fun refresh_entries/1),
    {reply, ok, State}.


handle_cast({add_oauth_creds, _, _}, #state{max_oauth_pairs = 0} = State) ->
    {noreply, State};

handle_cast({add_oauth_creds, OAuthPair, Creds}, State) ->
    case ets:lookup(?OAUTH_TO_CREDS, OAuthPair) of
    [{OAuthPair, {Creds, _ATime}}] ->
        {noreply, State};
    [] ->
        NewState = add_oauth_cache_entry(OAuthPair, Creds, erlang:now(), State),
        {noreply, NewState}
    end;

handle_cast({cache_hit, {_ConsumerKey, _Token} = OAuthPair}, State) ->
    case ets:lookup(?OAUTH_TO_CREDS, OAuthPair) of
    [{OAuthPair, {Credentials, ATime}}] ->
        cache_hit(OAuthPair, Credentials, ATime);
    _ ->
        ok
    end,
    {noreply, State};

handle_cast({cache_hit, UserName}, State) ->
    case ets:lookup(?BY_USER, UserName) of
    [{UserName, {Credentials, ATime}}] ->
        cache_hit(UserName, Credentials, ATime);
    _ ->
        ok
    end,
    {noreply, State}.


handle_info(_Msg, State) ->
    {noreply, State}.


terminate(_Reason, #state{db_notifier = Notifier}) ->
    couch_db_update_notifier:stop(Notifier),
    exec_if_auth_db(fun(AuthDb) -> catch couch_db:close(AuthDb) end),
    true = ets:delete(?BY_USER),
    true = ets:delete(?BY_ATIME),
    true = ets:delete(?STATE),
    true = ets:delete(?OAUTH_TO_CREDS),
    true = ets:delete(?USER_TO_OAUTH_PAIRS).


code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


clear_cache(State) ->
    exec_if_auth_db(fun(AuthDb) -> catch couch_db:close(AuthDb) end),
    true = ets:delete_all_objects(?BY_USER),
    true = ets:delete_all_objects(?BY_ATIME),
    true = ets:delete_all_objects(?OAUTH_TO_CREDS),
    true = ets:delete_all_objects(?USER_TO_OAUTH_PAIRS),
    State#state{cache_size = 0, num_oauth_pairs = 0}.

add_cache_entry(_, _, _, #state{max_cache_size = 0} = State) ->
    State;
add_cache_entry(UserName, Credentials, ATime, State) ->
    case State#state.cache_size >= State#state.max_cache_size of
    true ->
        free_mru_cache_entry();
    false ->
        ok
    end,
    true = ets:insert(?BY_ATIME, {ATime, UserName}),
    true = ets:insert(?BY_USER, {UserName, {Credentials, ATime}}),
    State#state{cache_size = couch_util:get_value(size, ets:info(?BY_USER))}.

free_mru_cache_entries(0) ->
    ok;
free_mru_cache_entries(N) when N > 0 ->
    free_mru_cache_entry(),
    free_mru_cache_entries(N - 1).

free_mru_cache_entry() ->
    MruTime = ets:last(?BY_ATIME),
    [{MruTime, UserName}] = ets:lookup(?BY_ATIME, MruTime),
    true = ets:delete(?BY_ATIME, MruTime),
    true = ets:delete(?BY_USER, UserName).

add_oauth_cache_entry(OAuthPair, {User, _, _, _, _} = Credentials, ATime, State) ->
    case State#state.num_oauth_pairs >= State#state.max_oauth_pairs of
    true ->
        free_oauth_mru_cache_entry();
    false ->
        ok
    end,
    true = ets:insert(?BY_ATIME_OAUTH, {ATime, OAuthPair}),
    true = ets:insert(?OAUTH_TO_CREDS, {OAuthPair, {Credentials, ATime}}),
    true = ets:insert(?USER_TO_OAUTH_PAIRS, {User, OAuthPair}),
    State#state{
        num_oauth_pairs = couch_util:get_value(size, ets:info(?OAUTH_TO_CREDS))
    }.

free_oauth_mru_cache_entries(0) ->
    ok;
free_oauth_mru_cache_entries(N) when N > 0 ->
    free_oauth_mru_cache_entry(),
    free_oauth_mru_cache_entries(N - 1).

free_oauth_mru_cache_entry() ->
    MruTime = ets:last(?BY_ATIME_OAUTH),
    [{MruTime, OAuthPair}] = ets:lookup(?BY_ATIME_OAUTH, MruTime),
    true = ets:delete(?BY_ATIME_OAUTH, MruTime),
    [{OAuthPair, {{User, _, _, _, _}, MruTime}}] = ets:lookup(
        ?OAUTH_TO_CREDS, OAuthPair),
    true = ets:delete(?OAUTH_TO_CREDS, OAuthPair),
    true = ets:delete_object(?USER_TO_OAUTH_PAIRS, {User, OAuthPair}).


cache_hit({_ConsumerKey, _Token} = OAuthPair, Credentials, ATime) ->
    NewATime = erlang:now(),
    true = ets:delete(?BY_ATIME_OAUTH, ATime),
    true = ets:insert(?BY_ATIME_OAUTH, {NewATime, OAuthPair}),
    true = ets:insert(?OAUTH_TO_CREDS, {OAuthPair, {Credentials, NewATime}});

cache_hit(UserName, Credentials, ATime) ->
    NewATime = erlang:now(),
    true = ets:delete(?BY_ATIME, ATime),
    true = ets:insert(?BY_ATIME, {NewATime, UserName}),
    true = ets:insert(?BY_USER, {UserName, {Credentials, NewATime}}).


refresh_entries(AuthDb) ->
    case reopen_auth_db(AuthDb) of
    nil ->
        ok;
    AuthDb2 ->
        case AuthDb2#db.update_seq > AuthDb#db.update_seq of
        true ->
            {ok, _, _} = couch_db:enum_docs_since(
                AuthDb2,
                AuthDb#db.update_seq,
                fun(DocInfo, _, _) -> refresh_entry(AuthDb2, DocInfo) end,
                AuthDb#db.update_seq,
                []
            ),
            true = ets:insert(?STATE, {auth_db, AuthDb2});
        false ->
            ok
        end
    end.


refresh_entry(Db, #doc_info{high_seq = DocSeq} = DocInfo) ->
    case is_user_doc(DocInfo) of
    {true, UserName} ->
        case ets:lookup(?BY_USER, UserName) of
        [] ->
            ok;
        [{UserName, {_OldCreds, ATime}}] ->
            {ok, Doc} = couch_db:open_doc(Db, DocInfo, [conflicts, deleted]),
            NewCreds = user_creds(Doc),
            true = ets:insert(?BY_USER, {UserName, {NewCreds, ATime}})
        end,
        % Purge oauth pairs, from the cache, associated with the previous
        % revisions of this doc. For simplicity and efficiency, we don't
        % if the new user doc revision has new oauth credentials, updated
        % oauth secrets or removed oauth credentials.
        case ets:lookup(?USER_TO_OAUTH_PAIRS, UserName) of
        [] ->
            ok;
        PairList ->
            lists:foreach(
                fun({Name, Pair}) when Name =:= UserName ->
                    [{Pair, {{Name, _, _, _, _}, T}}] = ets:lookup(
                        ?OAUTH_TO_CREDS, Pair),
                    true = ets:delete(?BY_ATIME_OAUTH, T),
                    true = ets:delete(?OAUTH_TO_CREDS, Pair)
                end,
                PairList),
            true = ets:delete(?USER_TO_OAUTH_PAIRS, UserName)
        end;
    false ->
        ok
    end,
    {ok, DocSeq}.


user_creds(#doc{deleted = true}) ->
    nil;
user_creds(#doc{} = Doc) ->
    {Creds} = couch_query_servers:json_doc(Doc),
    Creds.


is_user_doc(#doc_info{id = <<"org.couchdb.user:", UserName/binary>>}) ->
    {true, UserName};
is_user_doc(_) ->
    false.


maybe_refresh_cache() ->
    case cache_needs_refresh() of
    true ->
        ok = gen_server:call(?MODULE, refresh, infinity);
    false ->
        ok
    end.


cache_needs_refresh() ->
    exec_if_auth_db(
        fun(AuthDb) ->
            case reopen_auth_db(AuthDb) of
            nil ->
                false;
            AuthDb2 ->
                AuthDb2#db.update_seq > AuthDb#db.update_seq
            end
        end,
        false
    ).


reopen_auth_db(AuthDb) ->
    case (catch gen_server:call(AuthDb#db.main_pid, get_db, infinity)) of
    {ok, AuthDb2} ->
        AuthDb2;
    _ ->
        nil
    end.


exec_if_auth_db(Fun) ->
    exec_if_auth_db(Fun, ok).

exec_if_auth_db(Fun, DefRes) ->
    case ets:lookup(?STATE, auth_db) of
    [{auth_db, #db{} = AuthDb}] ->
        Fun(AuthDb);
    _ ->
        DefRes
    end.


open_auth_db() ->
    [{auth_db_name, DbName}] = ets:lookup(?STATE, auth_db_name),
    {ok, AuthDb} = ensure_users_db_exists(DbName, [sys_db]),
    AuthDb.


get_user_props_from_db(UserName) ->
    exec_if_auth_db(
        fun(AuthDb) ->
            Db = reopen_auth_db(AuthDb),
            DocId = <<"org.couchdb.user:", UserName/binary>>,
            try
                {ok, Doc} = couch_db:open_doc(Db, DocId, [conflicts]),
                {DocProps} = couch_query_servers:json_doc(Doc),
                DocProps
            catch
            _:_Error ->
                nil
            end
        end,
        nil
    ).

ensure_users_db_exists(DbName, Options) ->
    Options1 = [{user_ctx, #user_ctx{roles=[<<"_admin">>]}} | Options],
    case couch_db:open(DbName, Options1) of
    {ok, Db} ->
        ensure_auth_ddoc_exists(Db, <<"_design/_auth">>),
        {ok, Db};
    _Error ->
        {ok, Db} = couch_db:create(DbName, Options1),
        ok = ensure_auth_ddoc_exists(Db, <<"_design/_auth">>),
        {ok, Db}
    end.

ensure_auth_ddoc_exists(Db, DDocId) ->
    case couch_db:open_doc(Db, DDocId) of
    {not_found, _Reason} ->
        {ok, AuthDesign} = auth_design_doc(DDocId),
        {ok, _Rev} = couch_db:update_doc(Db, AuthDesign, []);
    _ ->
        ok
    end,
    ok.

auth_design_doc(DocId) ->
    DocProps = [
        {<<"_id">>, DocId},
        {<<"language">>,<<"javascript">>},
        {<<"validate_doc_update">>, ?AUTH_DB_DOC_VALIDATE_FUNCTION}
    ],
    {ok, couch_doc:from_json_obj({DocProps})}.
