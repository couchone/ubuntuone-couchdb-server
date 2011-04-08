// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License.  You may obtain a copy
// of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
// License for the specific language governing permissions and limitations under
// the License.

couchTests.oauth_cache = function(debug) {

  if (debug) debugger;

  var usersDb = new CouchDB("test_suite_users",{"X-Couch-Full-Commit":"false"});
  var host = CouchDB.host;
  var server_config = [
    {
      section: "httpd",
      key: "WWW-Authenticate",
      value: 'OAuth'
    },
    {
      section: "couch_httpd_auth",
      key: "secret",
      value: generateSecret(64)
    },
    {
      section: "couch_httpd_auth",
      key: "authentication_db",
      value: usersDb.name
    },
    {
      section: "couch_httpd_oauth",
      key: "use_user_db",
      value: "true"
    },
    {
      section: "couch_httpd_auth",
      key: "oauth_cache_size",
      value: "3"
    },
    {
      section: "couch_httpd_auth",
      key: "auth_cache_size",
      value: "3"
    }
  ];


  // Simple secret key generator
  function generateSecret(length) {
    var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var secret = '';
    for (var i = 0; i < length; i++) {
      secret += tab.charAt(Math.floor(Math.random() * 64));
    }
    return secret;
  }


  function hits() {
    var hits = CouchDB.requestStats("couchdb", "auth_cache_hits", true);
    return hits.current || 0;
  }

  function misses() {
    var misses = CouchDB.requestStats("couchdb", "auth_cache_misses", true);
    return misses.current || 0;
  }


  var fdmanana = CouchDB.prepareUserDoc({
    name: "fdmanana",
    roles: ["dev"],
    oauth: {
      consumer_keys: {
        "key_foo": "bar"
      },
      tokens: {
        "tok1": "123"
      }
    },
    delegations: [
      {
        "database": "test_db",
        "description": "test",
        "name": "fil",
        "roles": ["cooker", "foo"],
        "oauth": {
          "token": "fil_token",
          "token_secret": "fil_token_secret",
          "consumer_key": "fil_consumer_key",
          "consumer_secret": "fil_consumer_secret"
        }
      }
    ]
  }, "qwerty");

  var joe = CouchDB.prepareUserDoc({
    name: "joe",
    roles: ["foo", "bar"],
    oauth: {
      consumer_keys: {
        "key_joe_1": "one",
        "key_joe_2": "two"
      },
      tokens: {
        "tok_joe_1": "zxc",
        "tok_joe_2": "abc"
      }
    }
  }, "erl");


  function oauthRequest(method, path, message, accessor, body) {
    message.action = path;
    message.method = method || 'GET';
    OAuth.SignatureMethod.sign(message, accessor);
    var parameters = message.parameters;
    if (method == "POST" || method == "GET") {
      if (method == "GET") {
        return CouchDB.request("GET", OAuth.addToURL(path, parameters));
      } else {
        return CouchDB.request("POST", path, {
          headers: {"Content-Type": "application/x-www-form-urlencoded"},
          body: OAuth.formEncode(parameters)
        });
      }
    } else {
      return CouchDB.request(method, path, {
        headers: {
          Authorization: OAuth.getAuthorizationHeader('', parameters)
        },
        body: body
      });
    }
  }


  function cacheTestFun() {
    var fdmanana_oauth_msg, fdmanana_oauth_accessor;
    var joe_oauth_msg, joe_oauth_accessor, joe_oauth_msg2, joe_oauth_accessor2;
    var del_oauth_msg, del_oauth_accessor;
    var xhr, data, user_doc, doc;
    var hits_before, misses_before, hits_after, misses_after;

    delete fdmanana._rev;
    T(usersDb.save(fdmanana).ok);
    delete joe._rev;
    T(usersDb.save(joe).ok);

    fdmanana_oauth_msg = {
      parameters: {
        oauth_signature_method: "HMAC-SHA1",
        oauth_consumer_key: "key_foo",
        oauth_token: "tok1",
        oauth_version: "1.0"
      }
    };
    fdmanana_oauth_accessor = {
      consumerSecret: "bar",
      tokenSecret: "123"
    };

    del_oauth_msg = {
      parameters: {
        oauth_signature_method: "HMAC-SHA1",
        oauth_consumer_key: "fil_consumer_key",
        oauth_token: "fil_token",
        oauth_version: "1.0"
      }
    };
    del_oauth_accessor = {
      consumerSecret: "fil_consumer_secret",
      tokenSecret: "fil_token_secret"
    };

    joe_oauth_msg = {
      parameters: {
        oauth_signature_method: "HMAC-SHA1",
        oauth_consumer_key: "key_joe_1",
        oauth_token: "tok_joe_1",
        oauth_version: "1.0"
      }
    };
    joe_oauth_accessor = {
      consumerSecret: "one",
      tokenSecret: "zxc"
    };
    joe_oauth_msg2 = {
      parameters: {
        oauth_signature_method: "HMAC-SHA1",
        oauth_consumer_key: "key_joe_2",
        oauth_token: "tok_joe_2",
        oauth_version: "1.0"
      }
    };
    joe_oauth_accessor2 = {
      consumerSecret: "two",
      tokenSecret: "abc"
    };

    hits_before = hits();
    misses_before = misses();

    xhr = oauthRequest(
      "GET", "http://" + host + "/_session",
      fdmanana_oauth_msg, fdmanana_oauth_accessor);
    TEquals(200, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals(true, data.ok);
    TEquals("fdmanana", data.userCtx.name);

    hits_after = hits();
    misses_after = misses();

    // +2, miss on user doc and oauth credentials
    TEquals((misses_before + 2), misses_after);
    TEquals(hits_before, hits_after);

    hits_before = hits_after;
    misses_before = misses_after;

    xhr = oauthRequest(
      "GET", "http://" + host + "/_session",
      fdmanana_oauth_msg, fdmanana_oauth_accessor);
    TEquals(200, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals(true, data.ok);
    TEquals("fdmanana", data.userCtx.name);

    hits_after = hits();
    misses_after = misses();

    TEquals(misses_before, misses_after);
    // +1, oauth cache hit, no user doc lookup
    TEquals((hits_before + 1), hits_after);

    hits_before = hits_after;
    misses_before = misses_after;

    xhr = oauthRequest(
      "GET", "http://" + host + "/_session",
      joe_oauth_msg, joe_oauth_accessor);
    TEquals(200, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals(true, data.ok);
    TEquals("joe", data.userCtx.name);

    hits_after = hits();
    misses_after = misses();

    // +2, miss on user doc and oauth credentials
    TEquals((misses_before + 2), misses_after);
    TEquals(hits_before, hits_after);

    hits_before = hits_after;
    misses_before = misses_after;

    xhr = oauthRequest(
      "GET", "http://" + host + "/_session",
      joe_oauth_msg, joe_oauth_accessor);
    TEquals(200, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals(true, data.ok);
    TEquals("joe", data.userCtx.name);

    hits_after = hits();
    misses_after = misses();

    TEquals(misses_before, misses_after);
    // +1, oauth cache hit, no user doc lookup
    TEquals((hits_before + 1), hits_after);

    hits_before = hits_after;
    misses_before = misses_after;

    // use joe's second token and consumer key

    xhr = oauthRequest(
      "GET", "http://" + host + "/_session",
      joe_oauth_msg2, joe_oauth_accessor2);
    TEquals(200, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals(true, data.ok);
    TEquals("joe", data.userCtx.name);

    hits_after = hits();
    misses_after = misses();

    // +1, miss on oauth credentials
    TEquals((misses_before + 1), misses_after);
    // +1 because joe's user doc is cached
    TEquals((hits_before + 1), hits_after);

    hits_before = hits_after;
    misses_before = misses_after;

    xhr = oauthRequest(
      "GET", "http://" + host + "/_session",
      joe_oauth_msg2, joe_oauth_accessor2);
    TEquals(200, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals(true, data.ok);
    TEquals("joe", data.userCtx.name);

    hits_after = hits();
    misses_after = misses();

    TEquals(misses_before, misses_after);
    // +1 because joe's user doc is cached
    TEquals((hits_before + 1), hits_after);

    hits_before = hits_after;
    misses_before = misses_after;

    // test delegated OAuth credentials in fdmanana's user doc
    xhr = oauthRequest(
      "GET", "http://" + host + "/_session", del_oauth_msg, del_oauth_accessor);
    TEquals(200, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals(true, data.ok);
    TEquals("fil.delegated.fil_token", data.userCtx.name);

    hits_after = hits();
    misses_after = misses();

    // +1, miss on oauth credentials only
    TEquals((misses_before + 1), misses_after);
    TEquals(hits_before, hits_after);

    hits_before = hits_after;
    misses_before = misses_after;

    xhr = oauthRequest(
      "GET", "http://" + host + "/_session", del_oauth_msg, del_oauth_accessor);
    TEquals(200, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals(true, data.ok);
    TEquals("fil.delegated.fil_token", data.userCtx.name);

    hits_after = hits();
    misses_after = misses();

    TEquals(misses_before, misses_after);
    // +1, cache hit on oauth credentials, no user doc lookup
    TEquals((hits_before + 1), hits_after);

    hits_before = hits_after;
    misses_before = misses_after;

    // Authenticate with joe's second token and consumer key again.
    // Because the OAuth cache uses a MRU eviction policy, it should
    // cause a cache miss.

    xhr = oauthRequest(
      "GET", "http://" + host + "/_session",
      joe_oauth_msg2, joe_oauth_accessor2);
    TEquals(200, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals(true, data.ok);
    TEquals("joe", data.userCtx.name);

    hits_after = hits();
    misses_after = misses();

    // 1 cache miss on oauth credentials, no user doc lookup
    TEquals((misses_before + 1), misses_after);
    // +1, cache hit when getting Joe's user doc
    TEquals((hits_before + 1), hits_after);

    hits_before = hits_after;
    misses_before = misses_after;

    // Update Joe's first token secret. This should make the cache daemon
    // purge all the oauth credentials defined in Joe's user doc.

    joe.oauth.tokens["tok_joe_1"] = "new_secret";
    T(usersDb.save(joe).ok);

    joe_oauth_accessor.tokenSecret = "new_secret";
    xhr = oauthRequest(
      "GET", "http://" + host + "/_session",
      joe_oauth_msg, joe_oauth_accessor);
    TEquals(200, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals(true, data.ok);
    TEquals("joe", data.userCtx.name);

    hits_after = hits();
    misses_after = misses();

    // 1 cache miss on oauth credentials, no user doc lookup
    TEquals((misses_before + 1), misses_after);
    TEquals((hits_before + 1), hits_after, "cache hits +1, user doc in cache");

    hits_before = hits_after;
    misses_before = misses_after;

    // delete user, oauth authentication should fail
    T(usersDb.deleteDoc(fdmanana).ok);
    xhr = oauthRequest(
      "GET", "http://" + host + "/_session",
      fdmanana_oauth_msg, fdmanana_oauth_accessor);
    TEquals(400, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals("invalid_consumer_token_pair", data.error);

    hits_after = hits();
    misses_after = misses();

    // 1 cache miss on user doc, no oauth credentials lookup
    TEquals((misses_before + 1), misses_after);
    TEquals(hits_before, hits_after);
  }


  usersDb.deleteDb();
  run_on_modified_server(server_config, cacheTestFun);

  // cleanup
  usersDb.deleteDb();

};
