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

-export([oauth_authentication_handler/1, handle_oauth_req/1, consumer_lookup/2]).

-record(oauth_callback_params, {
    consumer,
    token,
    token_secret,
    url,
    signature,
    params,
    username,
    roles
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
        roles = Roles
    } = CbParams,
    case oauth:verify(Sig, Method, Url, Params, Consumer, TokenSecret) of
    true ->
        set_user_ctx(Req, User, Roles);
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
            [oauth:signature(Method), Url, Params, Consumer, TokenSecret]),
        Req
    end.

% Look up the consumer key and get the roles to give the consumer
set_user_ctx(_Req, undefined, _DelegationRoles) ->
    throw({bad_request, unknown_oauth_token});
set_user_ctx(Req, Name, undefined) ->
    case couch_auth_cache:get_user_creds(Name) of
        nil ->
            ?LOG_DEBUG("OAuth handler: user ~p credentials not found", [Name]),
            Req;
        User ->
            Roles = couch_util:get_value(<<"roles">>, User, []),
            Req#httpd{user_ctx=#user_ctx{name=Name, roles=Roles}}
    end;
set_user_ctx(Req, Name, DelegationRoles) ->
    ?LOG_DEBUG("Setting delegated oauth user_ctx, username: ~p, roles: ~p",
        [Name, DelegationRoles]),
    Req#httpd{user_ctx = #user_ctx{name = Name, roles = DelegationRoles}}.

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
                        invalid_consumer ->
                            couch_httpd:send_error(
                                Req, 400,
                                <<"invalid_consumer">>,
                                <<"Invalid consumer (key or signature method).">>);
                        {error, {Error, Reason}} ->
                            couch_httpd:send_error(Req, 400, Error, Reason)
                    end
            end;
        _ ->
            couch_httpd:send_error(Req, 400, <<"invalid_oauth_version">>, <<"Invalid OAuth version.">>)
    end.

get_oauth_callback_params(ConsumerKey, Params, Url) ->
    Token = couch_util:get_value("oauth_token", Params),
    SigMethod = sig_method(Params),
    CbParams0 = #oauth_callback_params{
        token = Token,
        signature = couch_util:get_value("oauth_signature", Params),
        params = proplists:delete("oauth_signature", Params),
        url = Url
    },
    case couch_auth_cache:get_user_creds({ConsumerKey, Token}) of
    nil ->
        case consumer_key_secret(ConsumerKey) of
        undefined ->
            invalid_consumer;
        {error, _} = Err ->
            Err;
        ConsumerSecret ->
            case access_token_info(Token) of
            {error, _} = Err ->
                Err;
            [undefined, undefined | _] ->
                CbParams = CbParams0#oauth_callback_params{
                    consumer = {ConsumerKey, ConsumerSecret, SigMethod}
                },
                {ok, CbParams};
            [TokenSecret, User1 | Rest] ->
                User = ?l2b(User1),
                Roles = case Rest of
                [] ->
                    case couch_auth_cache:get_user_creds(User) of
                    nil ->
                        undefined;
                    UserCreds ->
                        couch_util:get_value(<<"roles">>, UserCreds, [])
                    end;
                [DelegatedRoles] ->
                    DelegatedRoles
                end,
                CbParams = CbParams0#oauth_callback_params{
                    consumer = {ConsumerKey, ConsumerSecret, SigMethod},
                    token_secret = TokenSecret,
                    username = User,
                    roles = Roles
                },
                ?LOG_DEBUG("Got OAuth credentials, for ConsumerKey ~s and Token ~s, "
                    "from the views, User: ~s, Roles: ~p, ConsumerSecret: ~s, "
                    "TokenSecret: ~s",
                    [ConsumerKey, Token, User, Roles, ConsumerSecret, TokenSecret]),
                ok = couch_auth_cache:add_oauth_creds(
                    {ConsumerKey, Token},
                    {User, Roles, ConsumerSecret, TokenSecret}),
                {ok, CbParams}
            end
        end;
    {UserName, Roles, ConsumerSecret, TokenSecret} ->
        ?LOG_DEBUG("Got OAuth credentials, for ConsumerKey ~s and Token ~s, "
            "from cache, User: ~s, Roles: ~p, ConsumerSecret: ~s, "
            "TokenSecret: ~s",
            [ConsumerKey, Token, UserName, Roles, ConsumerSecret, TokenSecret]),
        CbParams = CbParams0#oauth_callback_params{
            consumer = {ConsumerKey, ConsumerSecret, SigMethod},
            token_secret = TokenSecret,
            username = UserName,
            roles = Roles
        },
        {ok, CbParams}
    end.

consumer_lookup(_Key, undefined) ->
    none;
consumer_lookup(Key, SignatureMethod) ->
    case consumer_key_secret(Key) of
        undefined -> none;
        {error, _} = Err -> Err;
        Secret -> {Key, Secret, SignatureMethod}
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

consumer_key_secret(Key) ->
    case use_auth_db() of
    {ok, Db} ->
        Secret =
        case query_map_view(Db, ?DDOC_ID, <<"consumer_key_secret">>, Key) of
        [] ->
            undefined;
        [Sec] ->
            ?b2l(Sec);
        Secs ->
            Reason = iolist_to_binary(
                io_lib:format("Can't map OAuth consumer key ~s to a single user "
                    "document. It is referenced by ~p user documents.",
                    [Key, length(Secs)])),
            ?LOG_ERROR("~s", [Reason]),
            {error, {<<"oauth_consumer_key">>, Reason}}
        end,
        couch_db:close(Db),
        Secret;
    nil ->
        couch_config:get("oauth_consumer_secrets", Key)
    end.

access_token_info(Token) ->
    case use_auth_db() of
    {ok, Db} ->
        Info =
        case query_map_view(Db, ?DDOC_ID, <<"access_token_info">>, Token) of
        [] ->
            [undefined, undefined];
        [[TokenSecret, Username | DelegatedRoles]] ->
            [?b2l(TokenSecret), ?b2l(Username) | DelegatedRoles];
        Secrets ->
            UserList = [?b2l(U) || [_, U | _] <- Secrets],
            Reason = iolist_to_binary(
                io_lib:format("Can't map OAuth token ~s to a single user "
                    "document. It is mapped to the following users: ~s.",
                    [Token, string:join(UserList, ", ")])),
            ?LOG_ERROR("~s", [Reason]),
            {error, {<<"oauth_token">>, Reason}}
        end,
        couch_db:close(Db),
        Info;
    nil ->
        [
            couch_config:get("oauth_token_secrets", Token),
            couch_config:get("oauth_token_users", Token)
        ]
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
                {<<"consumer_key_secret">>,
                    {[
                        {<<"map">>, consumer_key_secret_map_fun()}
                    ]}
                },
                {<<"access_token_info">>,
                    {[
                        {<<"map">>, access_token_info_map_fun()}
                    ]}
                }
            ]}
        }
    ]},
    {ok, couch_doc:from_json_obj(Json)}.

consumer_key_secret_map_fun() ->
    % map results =>  key: consumer_key, value: consumer_secret
    <<"
        function(doc) {
            if (doc.type === 'user' && doc.oauth && doc.oauth.consumer_keys) {
                for (var consumer_key in doc.oauth.consumer_keys) {
                    emit(consumer_key, doc.oauth.consumer_keys[consumer_key]);
                }
                var dels = doc.delegations || [];
                for (var i = 0; i < dels.length; i++) {
                    emit(dels[i].oauth.consumer_key,
                        dels[i].oauth.consumer_secret);
                }
            }
        }
    ">>.

access_token_info_map_fun() ->
    % map results =>
    %     key: access_token,
    %     value: [access_token_secret, username] ||
    %            [access_token_secret, delegation_username, delegation_roles]
    % (username == resource owner in OAuth's jargon)
    % (For 2-legged OAuth the consumer is the same as the resource owner)
    <<"
        function(doc) {
            if (doc.type === 'user' && doc.oauth && doc.oauth.tokens) {
                for (var token in doc.oauth.tokens) {
                    emit(token, [doc.oauth.tokens[token], doc.name]);
                }
                var dels = doc.delegations || [];
                var del_name, del_roles;
                for (var i = 0; i < dels.length; i++) {
                    del_name = dels[i].name + '.delegated.' + dels[i].database;
                    del_roles = dels[i].roles || [];
                    emit(dels[i].oauth.token,
                        [dels[i].oauth.token_secret, del_name, del_roles]);
                }
            }
        }
    ">>.

query_map_view(Db, DesignId, ViewName, Key1) ->
    Key = ?l2b(Key1),
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
    _ ->
        []
    end.
