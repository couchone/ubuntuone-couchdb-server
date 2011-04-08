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

couchTests.oauth_delegation = function(debug) {

  if (debug) debugger;

  var usersDb = new CouchDB("test_suite_users",{"X-Couch-Full-Commit":"false"});
  var host = CouchDB.host;
  var authorization_url = "/_oauth/authorize";
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
        "key_foo": "bar"
      },
      tokens: {
        "tok1": "123"
      }
    }
  }, "qwerty");

  var damien = CouchDB.prepareUserDoc({
    name: "damien",
    roles: ["creator"],
    oauth: {
      consumer_keys: {
        "key_damien": "katz"
      },
      tokens: {
        "token_damien": "katz"
      }
    },
    delegations: [
      {
        "databases": ["test_db"],
        "description": "test",
        "name": "twitter",
        "roles": ["cooker", "foo"],
        "oauth": {
          "token": "twitter_token_2",
          "token_secret": "twitter_token_secret_2",
          "consumer_key": "twitter_consumer_key",
          "consumer_secret": "twitter_consumer_secret"
        }
      }
    ]
  }, "qwerty");


  // computed in Erlang with couch_util:to_hex(couch_util:md5(UserName))
  // (there's no JavaScript MD5 lib shipped with CouchDB)
  var user_hashes = {
    "fdmanana": "9ecd64427022200cfe955884e6d68678",
    "damien": "5f31769db16ce3556b416de8d4fb2fff"
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

  function encDbPath(username, dbname) {
    return encodeURIComponent(dbPath(username, dbname));
  }


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


  function delegateTestFun() {
    var oauth_msg, oauth_accessor;
    var twitter_oauth_msg, twitter_oauth_accessor;
    var xhr, data, user_doc, doc;

    (new CouchDB(dbPath("fdmanana", "test_db"))).deleteDb();

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

    // let the user fdmanana create its database and add one doc
    xhr = oauthRequest(
      "PUT", "http://" + host + "/" + encDbPath("fdmanana", "test_db"),
       oauth_msg, oauth_accessor);
    TEquals(201, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals(true, data.ok);

    doc = {
      _id: "doc1",
      value: 111
    };
    xhr = oauthRequest(
      "PUT", "http://" + host + "/" + encDbPath("fdmanana", "test_db") +
        "/" + doc._id,
      oauth_msg, oauth_accessor, JSON.stringify(doc));
    TEquals(201, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals(true, data.ok);

    // let the user fdmanana add its own delegations to its user document
    xhr = oauthRequest(
      "GET", "http://" + host + "/" + usersDb.name + "/" +
        CouchDB.user_prefix + "fdmanana",
      oauth_msg, oauth_accessor);
    TEquals(200, xhr.status);
    user_doc = JSON.parse(xhr.responseText);

    user_doc.delegations = [
      {
        "databases": ["test_db"],
        "description": "test",
        "name": "twitter",
        "roles": ["cooker", "foo"],
        "oauth": {
          "token": "twitter_token_1",
          "token_secret": "twitter_token_secret_1",
          "consumer_key": "twitter_consumer_key",
          "consumer_secret": "twitter_consumer_secret"
        }
      }
    ];

    xhr = oauthRequest(
      "PUT", "http://" + host + "/" + usersDb.name + "/" +
        CouchDB.user_prefix + "fdmanana?rev=" + user_doc._rev,
      oauth_msg, oauth_accessor, JSON.stringify(user_doc));
    TEquals(201, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals(true, data.ok);


    twitter_oauth_msg = {
      parameters: {
        oauth_signature_method: "HMAC-SHA1",
        oauth_consumer_key: "twitter_consumer_key",
        oauth_token: "twitter_token_1",
        oauth_version: "1.0"
      }
    };
    twitter_oauth_accessor = {
      consumerSecret: "twitter_consumer_secret",
      tokenSecret: "twitter_token_secret_1"
    };

    // check that the delegated user twitter can login
    xhr = oauthRequest(
      "GET", "http://" + host + "/_session", twitter_oauth_msg, twitter_oauth_accessor);
    TEquals(200, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals(true, data.ok);
    TEquals("object", typeof data.userCtx);
    TEquals("twitter.delegated.twitter_token_1", data.userCtx.name);
    TEquals(true, data.userCtx.roles instanceof Array);
    TEquals(2, data.userCtx.roles.length);
    TEquals("cooker.delegated.twitter_token_1", data.userCtx.roles[0]);
    TEquals("foo.delegated.twitter_token_1", data.userCtx.roles[1]);
    TEquals("oauth", data.info.authenticated);

    // check if the delegated user Twitter can access fdmanana's database
    // before his name or roles are added to that database's security
    // object - shouldn't be possible

//     xhr = oauthRequest(
//       "GET", "http://" + host + "/" + encDbPath("fdmanana", "test_db"),
//       twitter_oauth_msg, twitter_oauth_accessor);
//     TEquals(401, xhr.status);
//     data = JSON.parse(xhr.responseText);
//     TEquals("unauthorized", data.error);

//     // now user fdmanana adds delegated user twitter to the security object
//     var sec_obj = {
//       admins: {
//         names: ["fdmanana"]
//       },
//       readers: {
//         names: ["twitter.delegated.test_db"]
//       }
//     };
//     xhr = oauthRequest(
//       "PUT", "http://" + host + "/" + encDbPath("fdmanana", "test_db") +
//         "/_security",
//       oauth_msg, oauth_accessor, JSON.stringify(sec_obj));
//     TEquals(200, xhr.status);
//     data = JSON.parse(xhr.responseText);
//     TEquals(true, data.ok);

    // twitter should now be able to access the database
    xhr = oauthRequest(
      "GET", "http://" + host + "/" + encDbPath("fdmanana", "test_db"),
      twitter_oauth_msg, twitter_oauth_accessor);
    TEquals(200, xhr.status);

    xhr = oauthRequest(
      "GET", "http://" + host + "/" + encDbPath("fdmanana", "test_db") + "/doc1",
      twitter_oauth_msg, twitter_oauth_accessor);
    TEquals(200, xhr.status);
    var doc_copy = JSON.parse(xhr.responseText);
    TEquals(111, doc_copy.value);

    var new_doc = {
      _id: "twitter_doc",
      value: 666
    };
    xhr = oauthRequest(
      "PUT", "http://" + host + "/" + encDbPath("fdmanana", "test_db") +
        "/" + new_doc._id,
      twitter_oauth_msg, twitter_oauth_accessor, JSON.stringify(new_doc));
    TEquals(201, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals(true, data.ok);

    // unless added to the admins of fdmanana's database security object,
    // twitter can't write design documents to it
    new_doc = {
      _id: "_design/twitter",
      value: "ddoc"
    };
    xhr = oauthRequest(
      "PUT", "http://" + host + "/" + encDbPath("fdmanana", "test_db") +
        "/" + new_doc._id,
      twitter_oauth_msg, twitter_oauth_accessor, JSON.stringify(new_doc));
    TEquals(401, xhr.status);

    // now add one of twitter's roles into the security object of the database
    var sec_obj = {
      admins: {
        names: ["fdmanana"],
        roles: ["qwerty", "cooker.delegated.twitter_token_1"]
      },
      readers: {
        names: ["twitter.delegated.test_db"]
      }
    };
    xhr = oauthRequest(
      "PUT", "http://" + host + "/" + encDbPath("fdmanana", "test_db") +
        "/_security",
      oauth_msg, oauth_accessor, JSON.stringify(sec_obj));
    TEquals(200, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals(true, data.ok);

    xhr = oauthRequest(
      "PUT", "http://" + host + "/" + encDbPath("fdmanana", "test_db") +
        "/" + new_doc._id,
      twitter_oauth_msg, twitter_oauth_accessor, JSON.stringify(new_doc));
    TEquals(201, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals(true, data.ok);

    // let user fdmanana create another database
    xhr = oauthRequest(
      "PUT", "http://" + host + "/" + encDbPath("fdmanana", "top_secret"),
       oauth_msg, oauth_accessor);
    TEquals(201, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals(true, data.ok);

    // twitter should not be able to access the new database
    xhr = oauthRequest(
      "GET", "http://" + host + "/" + encDbPath("fdmanana", "top_secret"),
      twitter_oauth_msg, twitter_oauth_accessor);
    TEquals(401, xhr.status);


    // add another user doc which defines a delegation for the same consumer as
    // defined in fdmanana's user doc
    (new CouchDB(dbPath("damien", "test_db"))).deleteDb();

    delete damien._rev;
    T(usersDb.save(damien).ok);

    oauth_msg = {
      parameters: {
        oauth_signature_method: "HMAC-SHA1",
        oauth_consumer_key: "key_damien",
        oauth_token: "token_damien",
        oauth_version: "1.0"
      }
    };
    oauth_accessor = {
      consumerSecret: "katz",
      tokenSecret: "katz"
    };

    // let the user damien create its database and add one doc
    xhr = oauthRequest(
      "PUT", "http://" + host + "/" + encDbPath("damien", "test_db"),
       oauth_msg, oauth_accessor);
    TEquals(201, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals(true, data.ok);

    doc = {
      _id: "docfoo",
      value: 111
    };
    xhr = oauthRequest(
      "PUT", "http://" + host + "/" + encDbPath("damien", "test_db") +
        "/" + doc._id,
      oauth_msg, oauth_accessor, JSON.stringify(doc));
    TEquals(201, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals(true, data.ok);

    twitter_oauth_msg.parameters.oauth_token = "twitter_token_2";
    twitter_oauth_accessor.tokenSecret = "twitter_token_secret_2";

    xhr = oauthRequest(
      "GET", "http://" + host + "/" + encDbPath("damien", "test_db"),
      twitter_oauth_msg, twitter_oauth_accessor);
    TEquals(200, xhr.status);

    xhr = oauthRequest(
      "GET", "http://" + host + "/" + encDbPath("damien", "test_db") + "/docfoo",
      twitter_oauth_msg, twitter_oauth_accessor);
    TEquals(200, xhr.status);
    doc_copy = JSON.parse(xhr.responseText);
    TEquals(111, doc_copy.value);
  }


  usersDb.deleteDb();
  run_on_modified_server(server_config, delegateTestFun);

  // cleanup
//  usersDb.deleteDb();
  (new CouchDB(dbPath("fdmanana", "test_db"))).deleteDb();
  (new CouchDB(dbPath("fdmanana", "top_secret"))).deleteDb();

};
