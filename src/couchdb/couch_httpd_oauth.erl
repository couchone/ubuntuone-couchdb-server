% Licensed under the Apache License, Version 2.0 (the "License"); you may not
% use this file except in compliance with the License.  You may obtain a copy of
% the License at
%
%   http://www.apache.org/licenses/LICENSE-2.0
%
% Unless required by applicable law or agreed to in writing, software
% distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
% WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
% License for the specific language governing permissions and limitations under
% the License.

-module(couch_httpd_oauth).
-include("couch_db.hrl").

-export([oauth_authentication_handler/1, handle_oauth_req/1]).
-import(couch_util, [
    get_value/2,
    get_value/3,
    to_binary/1
]).

-record(oauth_callback_params, {
    consumer,
    token,
    token_secret,
    url,
    signature,
    params,
    username,
    roles,
    database
}).

% OAuth auth handler using per-node user db
oauth_authentication_handler(Req) ->
    serve_oauth(Req, fun oauth_auth_callback/2, true).

oauth_auth_callback(Req, #oauth_callback_params{token_secret = undefined}) ->
    couch_httpd:send_error(
         Req, 400,
         <<"invalid_token">>, <<"Invalid OAuth token.">>);
oauth_auth_callback(#httpd{mochi_req = MochiReq} = Req, CbParams) ->
    Method = atom_to_list(MochiReq:get(method)),
    #oauth_callback_params{
        consumer = Consumer,
        token_secret = TokenSecret,
        url = Url,
        signature = Sig,
        params = Params,
        username = User,
        roles = Roles,
        database = DelegationDb
    } = CbParams,
    case oauth:verify(Sig, Method, Url, Params, Consumer, TokenSecret) of
    true ->
        set_user_ctx(Req, User, Roles, DelegationDb);
    false ->
        ?LOG_DEBUG("OAuth handler: signature verification failed for user ~p",
            [User]),
        ?LOG_DEBUG("OAuth handler: received signature ~p", [Sig]),
        ?LOG_DEBUG("OAuth handler: HTTP method ~s", [Method]),
        ?LOG_DEBUG("OAuth handler: URL ~p", [Url]),
        ?LOG_DEBUG("OAuth handler: Parameters ~p", [Params]),
        ?LOG_DEBUG("OAuth handler: Consumer ~p, TokenSecret ~p",
            [Consumer, TokenSecret]),
        ?LOG_DEBUG("OAuth handler: expected signature ~p",
            [oauth:signature(Method, Url, Params, Consumer, TokenSecret)]),
        Req
    end.

% Look up the consumer key and get the roles to give the consumer
set_user_ctx(_Req, undefined, _DelegationRoles, _DelegationDb) ->
    throw({bad_request, unknown_oauth_token});
set_user_ctx(Req, Name, undefined, undefined) ->
    case couch_auth_cache:get_user_creds(Name) of
        nil ->
            ?LOG_DEBUG("OAuth handler: user ~p credentials not found", [Name]),
            Req;
        User ->
            Roles = couch_util:get_value(<<"roles">>, User, []),
            Req#httpd{user_ctx=#user_ctx{name=Name, roles=Roles}}
    end;
set_user_ctx(Req, Name, DelegationRoles, DelegationDb) ->
    ?LOG_DEBUG("Setting delegated oauth user_ctx, username: ~p, "
        "roles: ~p, database: ~p", [Name, DelegationRoles, DelegationDb]),
    Req#httpd{user_ctx = #user_ctx{
        name = Name,
        roles = DelegationRoles,
        delegated_databases = case DelegationDb of
            undefined ->
                null;
            _ ->
                [DelegationDb]
            end
    }}.

% OAuth request_token
handle_oauth_req(#httpd{path_parts=[_OAuth, <<"request_token">>], method=Method}=Req1) ->
    serve_oauth(Req1, fun(Req, CbParams) ->
        #oauth_callback_params{
            consumer = Consumer,
            token_secret = TokenSecret,
            url = Url,
            signature = Sig,
            params = Params
        } = CbParams,
        case oauth:verify(
            Sig, atom_to_list(Method), Url, Params, Consumer, TokenSecret) of
        true ->
            ok(Req, <<"oauth_token=requestkey&oauth_token_secret=requestsecret">>);
        false ->
            invalid_signature(Req)
        end
    end, false);
handle_oauth_req(#httpd{path_parts=[_OAuth, <<"authorize">>]}=Req) ->
    {ok, serve_oauth_authorize(Req)};
handle_oauth_req(#httpd{path_parts=[_OAuth, <<"access_token">>], method='GET'}=Req1) ->
    serve_oauth(Req1, fun(Req, CbParams) ->
        #oauth_callback_params{
            consumer = Consumer,
            token = Token,
            url = Url,
            signature = Sig,
            params = Params
        } = CbParams,
        case Token of
        "requestkey" ->
            case oauth:verify(
                Sig, "GET", Url, Params, Consumer, "requestsecret") of
            true ->
                ok(Req,
                    <<"oauth_token=accesskey&oauth_token_secret=accesssecret">>);
            false ->
                invalid_signature(Req)
            end;
        _ ->
            couch_httpd:send_error(
                Req, 400, <<"invalid_token">>, <<"Invalid OAuth token.">>)
        end
    end, false);
handle_oauth_req(#httpd{path_parts=[_OAuth, <<"access_token">>]}=Req) ->
    couch_httpd:send_method_not_allowed(Req, "GET").

invalid_signature(Req) ->
    couch_httpd:send_error(Req, 400, <<"invalid_signature">>, <<"Invalid signature value.">>).

% This needs to be protected i.e. force user to login using HTTP Basic Auth or form-based login.
serve_oauth_authorize(#httpd{method=Method}=Req1) ->
    case Method of
        'GET' ->
            % Confirm with the User that they want to authenticate the Consumer
            serve_oauth(Req1, fun(Req, CbParams) ->
                #oauth_callback_params{
                    consumer = Consumer,
                    token_secret = TokenSecret,
                    url = Url,
                    signature = Sig,
                    params = Params
                } = CbParams,
                case oauth:verify(
                    Sig, "GET", Url, Params, Consumer, TokenSecret) of
                true ->
                    ok(Req, <<"oauth_token=requestkey&",
                        "oauth_token_secret=requestsecret">>);
                false ->
                    invalid_signature(Req)
                end
            end, false);
        'POST' ->
            % If the User has confirmed, we direct the User back to the Consumer with a verification code
            serve_oauth(Req1, fun(Req, CbParams) ->
                #oauth_callback_params{
                    consumer = Consumer,
                    token_secret = TokenSecret,
                    url = Url,
                    signature = Sig,
                    params = Params
                } = CbParams,
                case oauth:verify(
                    Sig, "POST", Url, Params, Consumer, TokenSecret) of
                true ->
                    %redirect(oauth_callback, oauth_token, oauth_verifier),
                    ok(Req, <<"oauth_token=requestkey&",
                        "oauth_token_secret=requestsecret">>);
                false ->
                    invalid_signature(Req)
                end
            end, false);
        _ ->
            couch_httpd:send_method_not_allowed(Req1, "GET,POST")
    end.

serve_oauth(#httpd{mochi_req=MochiReq}=Req, Fun, FailSilently) ->
    % 1. In the HTTP Authorization header as defined in OAuth HTTP Authorization Scheme.
    % 2. As the HTTP POST request body with a content-type of application/x-www-form-urlencoded.
    % 3. Added to the URLs in the query part (as defined by [RFC3986] section 3).
    AuthHeader = case MochiReq:get_header_value("authorization") of
        undefined ->
            "";
        Else ->
            [Head | Tail] = re:split(Else, "\\s", [{parts, 2}, {return, list}]),
            case [string:to_lower(Head) | Tail] of
                ["oauth", Rest] -> Rest;
                _ -> ""
            end
    end,
    HeaderParams = oauth_uri:params_from_header_string(AuthHeader),
    %Realm = couch_util:get_value("realm", HeaderParams),
    Params = proplists:delete("realm", HeaderParams) ++ MochiReq:parse_qs(),
    ?LOG_DEBUG("OAuth Params: ~p", [Params]),
    case couch_util:get_value("oauth_version", Params, "1.0") of
        "1.0" ->
            case couch_util:get_value("oauth_consumer_key", Params, undefined) of
                undefined ->
                    case FailSilently of
                        true -> Req;
                        false -> couch_httpd:send_error(Req, 400, <<"invalid_consumer">>, <<"Invalid consumer.">>)
                    end;
                ConsumerKey ->
                    Url = couch_httpd:absolute_uri(Req, MochiReq:get(raw_path)),
                    case get_oauth_callback_params(ConsumerKey, Params, Url) of
                        {ok, CallbackParams} ->
                            Fun(Req, CallbackParams);
                        invalid_consumer_token_pair ->
                            couch_httpd:send_error(
                                Req, 400,
                                <<"invalid_consumer_token_pair">>,
                                <<"Invalid consumer and token pair.">>);
                        {error, {Error, Reason}} ->
                            couch_httpd:send_error(Req, 400, Error, Reason)
                    end
            end;
        _ ->
            couch_httpd:send_error(Req, 400, <<"invalid_oauth_version">>, <<"Invalid OAuth version.">>)
    end.

get_oauth_callback_params(ConsumerKey, Params, Url) ->
    Token = get_value("oauth_token", Params),
    SigMethod = sig_method(Params),
    CbParams0 = #oauth_callback_params{
        token = Token,
        signature = get_value("oauth_signature", Params),
        params = proplists:delete("oauth_signature", Params),
        url = Url
    },
    case couch_auth_cache:get_user_creds({ConsumerKey, Token}) of
    nil ->
        case oauth_credentials_info(Token, ConsumerKey) of
        nil ->
            invalid_consumer_token_pair;
        {error, _} = Err ->
            Err;
        {OauthCreds} ->
            User = get_value(<<"username">>, OauthCreds),
            ConsumerSecret = as_list(get_value(<<"consumer_secret">>, OauthCreds)),
            TokenSecret = as_list(get_value(<<"token_secret">>, OauthCreds)),
            case (User =:= undefined) orelse (ConsumerSecret =:= undefined) orelse
                 (TokenSecret =:= undefined) of
            true ->
                 invalid_consumer_token_pair;
            false ->
                case get_value(<<"delegation_db">>, OauthCreds, nil) of
                nil ->
                    case couch_auth_cache:get_user_creds(User) of
                    nil ->
                        Roles = undefined,
                        DelegationDb = undefined;
                    UserCreds ->
                        Roles = get_value(<<"roles">>, UserCreds, []),
                        DelegationDb = undefined
                    end;
                Db ->
                    Roles = get_value(<<"delegation_roles">>, OauthCreds),
                    DelegatorUser = get_value(<<"delegator">>, OauthCreds),
                    UserPrefix = couch_httpd_auth:username_to_prefix(DelegatorUser),
                    DelegationDb = <<UserPrefix/binary, Db/binary>>
                end,
                CbParams = CbParams0#oauth_callback_params{
                    consumer = {ConsumerKey, ConsumerSecret, SigMethod},
                    token_secret = TokenSecret,
                    username = User,
                    roles = Roles,
                    database = DelegationDb
                },
                ?LOG_DEBUG("Got OAuth credentials, for ConsumerKey ~p and Token ~p, "
                           "from the views, User: ~p, Roles: ~p, ConsumerSecret: ~p, "
                           "TokenSecret: ~p, DelegationDb: ~p",
                           [ConsumerKey, Token, User, Roles, ConsumerSecret,
                            TokenSecret, DelegationDb]),
                ok = couch_auth_cache:add_oauth_creds(
                    {ConsumerKey, Token},
                    {User, Roles, DelegationDb, ConsumerSecret, TokenSecret}),
                {ok, CbParams}
            end
        end;
    {UserName, Roles, DelegationDb, ConsumerSecret, TokenSecret} ->
        ?LOG_DEBUG("Got OAuth credentials, for ConsumerKey ~p and Token ~p, "
                   "from cache, User: ~p, Roles: ~p, ConsumerSecret: ~p, "
                   "TokenSecret: ~p, DelegationDb: ~p",
                   [ConsumerKey, Token, UserName, Roles, ConsumerSecret, TokenSecret, DelegationDb]),
        CbParams = CbParams0#oauth_callback_params{
            consumer = {ConsumerKey, ConsumerSecret, SigMethod},
            token_secret = TokenSecret,
            username = UserName,
            roles = Roles,
            database = DelegationDb
        },
        {ok, CbParams}
    end.

sig_method(Params) ->
    sig_method_1(couch_util:get_value("oauth_signature_method", Params)).
sig_method_1("PLAINTEXT") ->
    plaintext;
% sig_method_1("RSA-SHA1") ->
%    rsa_sha1;
sig_method_1("HMAC-SHA1") ->
    hmac_sha1;
sig_method_1(_) ->
    undefined.

ok(#httpd{mochi_req=MochiReq}, Body) ->
    {ok, MochiReq:respond({200, [], Body})}.


-define(DDOC_ID, <<"_design/oauth">>).

oauth_credentials_info(Token, ConsumerKey) ->
    case use_auth_db() of
    {ok, Db} ->
        case query_map_view(
            Db, ?DDOC_ID, <<"oauth_credentials">>, [?l2b(ConsumerKey), ?l2b(Token)]) of
        [] ->
            nil;
        [Creds] ->
            Creds;
        [_ | _] ->
            Reason = iolist_to_binary(
                io_lib:format("Found multiple OAuth credentials for the pair "
                              " (consumer_key: `~s`, token: `~s`)",
                              [to_binary(ConsumerKey), to_binary(Token)])),
            {error, {<<"oauth_token_consumer_key_pair">>, Reason}}
        end;
    nil ->
        {
            case couch_config:get("oauth_consumer_secrets", ConsumerKey) of
            undefined -> [];
            ConsumerSecret -> [{<<"consumer_secret">>, ?l2b(ConsumerSecret)}]
            end
            ++
            case couch_config:get("oauth_token_secrets", Token) of
            undefined -> [];
            TokenSecret -> [{<<"token_secret">>, ?l2b(TokenSecret)}]
            end
            ++
            case couch_config:get("oauth_token_users", Token) of
            undefined -> [];
            User -> [{<<"username">>, ?l2b(User)}]
            end
        }
    end.

use_auth_db() ->
    case couch_config:get("couch_httpd_oauth", "use_user_db", "false") of
    "false" ->
        nil;
    "true" ->
        AuthDb = open_auth_db(),
        ensure_oauth_views_exist(AuthDb),
        {ok, AuthDb}
    end.

open_auth_db() ->
    DbName = ?l2b(couch_config:get("couch_httpd_auth", "authentication_db")),
    DbOptions = [{user_ctx, #user_ctx{roles=[<<"_admin">>]}}, sys_db],
    {ok, AuthDb} = couch_db:open(DbName, DbOptions),
    AuthDb.

ensure_oauth_views_exist(AuthDb) ->
    case couch_db:open_doc(AuthDb, ?DDOC_ID, []) of
    {ok, _DDoc} ->
        ok;
    _ ->
        {ok, DDoc} = get_oauth_ddoc(),
        {ok, _Rev} = couch_db:update_doc(AuthDb, DDoc, [])
    end.

get_oauth_ddoc() ->
    Json = {[
        {<<"_id">>, ?DDOC_ID},
        {<<"language">>, <<"javascript">>},
        {<<"views">>,
            {[
                {<<"oauth_credentials">>,
                    {[
                        {<<"map">>, oauth_creds_map_fun()}
                    ]}
                }
            ]}
        }
    ]},
    {ok, couch_doc:from_json_obj(Json)}.

oauth_creds_map_fun() ->
    % map key is like [consumer_key, access_token]
    % map value is like
    %     {
    %         "consumer_secret": "foo",
    %         "token_secret": "bar",
    %         "username": "joe",
    %         "delegation_db": "databasename"
    %         "delegation_roles": ["foo", "bar"],
    %         "delegator": "username of the delegator user"
    %     }
    %
    % NOTE: delegation_db, delegation_roles and delegator are only defined if
    %       the entry corresponds to an oauth delegation
    <<"
        function(doc) {
            if (doc.type === 'user' && doc.oauth && doc.oauth.consumer_keys) {

                for (var consumer_key in doc.oauth.consumer_keys) {
                    for (var token in doc.oauth.tokens) {
                        var obj = {
                            'consumer_secret': doc.oauth.consumer_keys[consumer_key],
                            'token_secret': doc.oauth.tokens[token],
                            'username': doc.name
                        };
                        emit([consumer_key, token], obj);
                    }
                }

                var dels = doc.delegations || [];
                for (var i = 0; i < dels.length; i++) {
                    if ((typeof dels[i].oauth !== 'object') || (dels[i].oauth === null)) {
                        log('Missing oauth property for delegation index ' + i +
                            ' in user `' + doc.name + '` document.');
                        continue;
                    }
                    var db = dels[i].database;
                    var del_roles = dels[i].roles || [];
                    for (var r = 0; r < del_roles.length; r++) {
                        del_roles[r] = del_roles[r] + '.delegated.' + db;
                    }
                    var obj = {
                        'consumer_secret': dels[i].oauth.consumer_secret,
                        'token_secret': dels[i].oauth.token_secret,
                        'username': dels[i].name + '.delegated.' + dels[i].database,
                        'delegation_db': dels[i].database,
                        'delegation_roles': del_roles,
                        'delegator': doc.name
                    };
                    emit([dels[i].oauth.consumer_key, dels[i].oauth.token], obj);
                }
            }
        }
    ">>.

query_map_view(Db, DesignId, ViewName, Key) ->
    {ok, View, _Group} = couch_view:get_map_view(Db, DesignId, ViewName, nil),
    FoldlFun = fun({_Key_DocId, Value}, _, Acc) ->
        {ok, [Value | Acc]}
    end,
    ViewOptions = [
        {start_key, {Key, ?MIN_STR}},
        {end_key, {Key, ?MAX_STR}}
    ],
    case couch_view:fold(View, FoldlFun, [], ViewOptions) of
    {ok, _, Result} ->
        Result;
    Error ->
        ?LOG_ERROR("Warning: error querying map view `~s` (design document `~s`): ~s"
                   "~nReturning empty result set.",
                   [to_binary(ViewName), to_binary(DesignId), to_binary(Error)]),
        []
    end.

as_list(undefined) ->
    undefined;
as_list(B) when is_binary(B) ->
    ?b2l(B).
