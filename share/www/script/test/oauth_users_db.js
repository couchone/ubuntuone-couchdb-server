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

couchTests.oauth_users_db = function(debug) {
  // This tests OAuth authentication using the _users DB instead of the ini
  // configuration for storing OAuth tokens and secrets.

  if (debug) debugger;

  var usersDb = new CouchDB("test_suite_users",{"X-Couch-Full-Commit":"false"});
  var db = new CouchDB("test_suite_db", {"X-Couch-Full-Commit":"false"});
  var host = CouchDB.host;
  var authorization_url = "/_oauth/authorize";


  // Simple secret key generator
  function generateSecret(length) {
    var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var secret = '';
    for (var i = 0; i < length; i++) {
      secret += tab.charAt(Math.floor(Math.random() * 64));
    }
    return secret;
  }

  var fdmanana = CouchDB.prepareUserDoc({
    name: "fdmanana",
    roles: ["dev"],
    oauth: {
      consumer_keys: {
        "key_foo": "bar",
        "key_xpto": "mars"
      },
      tokens: {
        "salut": "ola",
        "tok1": "123"
      }
    }
  }, "qwerty");

  var joe = CouchDB.prepareUserDoc({
    name: "joe",
    roles: ["erlanger"],
    oauth: {
      consumer_keys: {
        "key_foo_2": "bar2",
        "key_xpto_2": "mars2"
      },
      tokens: {
        "salut_2": "ola2",
        "tok2": "666"
      }
    }
  }, "functional");


  // computed in Erlang with couch_util:to_hex(couch_util:md5(UserName))
  // (there's no JavaScript MD5 lib shipped with CouchDB)
  var user_hashes = {
    "joe":  "8ff32489f92f33416694be8fdc2d4c22",
    "fdmanana": "9ecd64427022200cfe955884e6d68678"
  };

  function userPrefix(username) {
    // same computation as couch_httpd_auth:username_to_prefix/1
    var p0 = user_hashes[username].substr(0, 3);
    var p1 = user_hashes[username].substr(3, 3);
    return "u/" + p0 + "/" + p1 + "/" + username + "/";
  }

  function dbPath(username, dbname) {
    return userPrefix(username) + dbname;
  }


  function oauthRequest(method, path, message, accessor) {
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
        headers: {Authorization: OAuth.getAuthorizationHeader('', parameters)}
      });
    }
  }


  var loginTestFun = function () {
    delete fdmanana._rev;
    T(usersDb.save(fdmanana).ok);

    var signatureMethods = ["PLAINTEXT", "HMAC-SHA1"];
    var message, xhr, responseMessage, accessor, data;

    for (var i = 0; i < signatureMethods.length; i++) {
      message = {
        parameters: {
          oauth_signature_method: signatureMethods[i],
          oauth_consumer_key: "key_foo",
          oauth_token: "tok1",
          oauth_version: "1.0"
        }
      };
      accessor = {
        consumerSecret: "bar",
        tokenSecret: "123"
      };

      xhr = oauthRequest("GET", "http://" + host + "/_oauth/request_token",
        message, accessor
      );
      T(xhr.status === 200);

      responseMessage = OAuth.decodeForm(xhr.responseText);

      // Obtaining User Authorization
      // Only needed for 3-legged OAuth
      //xhr = CouchDB.request("GET", authorization_url + '?oauth_token=' + responseMessage.oauth_token);
      //T(xhr.status === 200);

      xhr = oauthRequest("GET", "http://" + host + "/_session", message, accessor);
      T(xhr.status === 200);
      data = JSON.parse(xhr.responseText);
      T(data.ok);
      T(typeof data.userCtx === "object");
      T(data.userCtx.name === "fdmanana");
      T(data.userCtx.roles[0] === "dev");
      T(data.info.authenticated === "oauth");

      // test invalid token
      message.parameters.oauth_token = "not a token!";
      xhr = oauthRequest("GET", "http://" + host + "/_session",
        message, accessor
      );
      T(xhr.status === 400, "Request should be invalid.");

      // test invalid secret
      message.parameters.oauth_token = "tok1";
      accessor.tokenSecret = "badone";
      xhr = oauthRequest("GET", "http://" + host + "/_session",
        message, accessor
      );
      data = JSON.parse(xhr.responseText);
      T(data.userCtx.name === null);
      T(data.userCtx.roles.length === 1);
      T(data.userCtx.roles[0] === "_admin");
      T(data.info.authentication_handlers.indexOf("default") >= 0);
      T(data.info.authenticated === "default");
    }
  };


  function populate_db(db, docs) {
    for (var i = 0; i < docs.length; i++) {
      var d = docs[i];
      delete d._rev;
      T(db.save(d).ok);
    }
  }

  var replicationTestFun = function() {
    var host = CouchDB.host;
    var dbA = new CouchDB("test_suite_db_a", {"X-Couch-Full-Commit": "false"});
    var dbB = new CouchDB("test_suite_db_b", {"X-Couch-Full-Commit": "false"});
    var docs = makeDocs(0, 5);

    delete fdmanana._rev;
    delete joe._rev;
    T(usersDb.save(fdmanana).ok);
    T(usersDb.save(joe).ok);

    var repObj = {
      source: dbA.name,
      target: {
        url: 'http://' + host + '/' +
          encodeURIComponent(dbPath("fdmanana", dbB.name)),
        auth: {
          oauth: {
            consumer_secret: "bar",
            consumer_key: "key_foo",
            token_secret: "ola",
            token: "salut"
          }
        }
      }
    };

    var src = new CouchDB(dbA.name);
    src.deleteDb();
    T(src.createDb().ok);
    populate_db(src, docs);

    T(CouchDB.login("fdmanana", "qwerty").ok);
    var tgt = new CouchDB(dbPath("fdmanana", dbB.name));
    tgt.deleteDb();
    T(tgt.createDb().ok);
    CouchDB.logout();

    var repResult = CouchDB.replicate(repObj.source, repObj.target);
    T(repResult.ok === true);

    for (var i = 0; i < docs.length; i++) {
      var copy = tgt.open(docs[i]._id);
      T(copy !== null);
    }

    src.deleteDb();
    tgt.deleteDb();

    // test replication failure (wrong user OAuth credentials)
    T(src.createDb().ok);
    populate_db(src, docs);

    T(CouchDB.login("joe", "functional").ok);
    tgt = new CouchDB(dbPath("joe", dbB.name));
    tgt.deleteDb();
    T(tgt.createDb().ok);
    CouchDB.logout();

    repObj.target.url = 'http://' + host + '/' +
        encodeURIComponent(dbPath("joe", dbB.name));

    try {
      CouchDB.replicate(repObj.source, repObj.target);
      T(false, "replication should have failed");
    } catch (x) {
      TEquals("string", typeof x.error, "got an error when pull replicating");
    }

    src.deleteDb();
    tgt.deleteDb();
  };


  function duplicateCredentialsTest() {
    var oauth_msg, oauth_accessor;
    var xhr, data;

    delete fdmanana._rev;
    T(usersDb.save(fdmanana).ok);

    oauth_msg = {
      parameters: {
        oauth_signature_method: "HMAC-SHA1",
        oauth_consumer_key: "key_foo",
        oauth_token: "tok1",
        oauth_version: "1.0"
      }
    };
    oauth_accessor = {
      consumerSecret: "bar",
      tokenSecret: "123"
    };

    xhr = oauthRequest(
      "GET", "http://" + host + "/_session", oauth_msg, oauth_accessor);
    TEquals(200, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals(true, data.ok);
    TEquals("object", typeof data.userCtx);
    TEquals("fdmanana", data.userCtx.name);
    TEquals("dev", data.userCtx.roles[0]);
    TEquals("oauth", data.info.authenticated);

    // a different user doc, also with the consumer "key_foo" but with a
    // different consumer secret -> should lead to an error
    var hulk = CouchDB.prepareUserDoc({
      name: "hulk",
      roles: ["destroyer", "foo"],
      oauth: {
        consumer_keys: {
          "key_foo": "other_bar"
        },
        tokens: {
          "green": "muscles"
        }
      }
    }, "321");
    T(usersDb.save(hulk).ok);

    xhr = oauthRequest(
      "GET", "http://" + host + "/_session", oauth_msg, oauth_accessor);
    TEquals(400, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals("oauth_consumer_key", data.error);

    T(usersDb.deleteDoc(hulk));

    // a different user doc, also with the token "tok1" but with a different
    // token secret -> should lead to an error
    var ironMan = CouchDB.prepareUserDoc({
      name: "iron",
      roles: ["foobar"],
      oauth: {
        consumer_keys: {
          "iron_consumer": "steel"
        },
        tokens: {
          "tok1": "different_secret"
        }
      }
    }, "rusty");
    T(usersDb.save(ironMan).ok);

    xhr = oauthRequest(
      "GET", "http://" + host + "/_session", oauth_msg, oauth_accessor);
    TEquals(400, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals("oauth_token", data.error);
  }


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
    }
  ];

  usersDb.deleteDb();
  run_on_modified_server(server_config, loginTestFun);
  usersDb.deleteDb();
  run_on_modified_server(server_config, replicationTestFun);
  usersDb.deleteDb();
  run_on_modified_server(server_config, duplicateCredentialsTest);

  // cleanup
  usersDb.deleteDb();
  db.deleteDb();
};
