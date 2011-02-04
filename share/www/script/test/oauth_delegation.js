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


  // computed in Erlang with couch_util:to_hex(couch_util:md5(UserName))
  // (there's no JavaScript MD5 lib shipped with CouchDB)
  var user_hashes = {
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
    var joe_oauth_msg, joe_oauth_accessor;
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
        "database": "test_db",
        "description": "test",
        "name": "joe",
        "roles": ["cooker", "foo"],
        "oauth": {
          "token": "joe_token",
          "token_secret": "joe_token_secret",
          "consumer_key": "joe_consumer_key",
          "consumer_secret": "joe_consumer_secret"
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


    joe_oauth_msg = {
      parameters: {
        oauth_signature_method: "HMAC-SHA1",
        oauth_consumer_key: "joe_consumer_key",
        oauth_token: "joe_token",
        oauth_version: "1.0"
      }
    };
    joe_oauth_accessor = {
      consumerSecret: "joe_consumer_secret",
      tokenSecret: "joe_token_secret"
    };

    // check that the delegated user joe can login
    xhr = oauthRequest(
      "GET", "http://" + host + "/_session", joe_oauth_msg, joe_oauth_accessor);
    TEquals(200, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals(true, data.ok);
    TEquals("object", typeof data.userCtx);
    TEquals("joe.delegated.test_db", data.userCtx.name);
    TEquals(true, data.userCtx.roles instanceof Array);
    TEquals(2, data.userCtx.roles.length);
    TEquals("cooker.delegated.test_db", data.userCtx.roles[0]);
    TEquals("foo.delegated.test_db", data.userCtx.roles[1]);
    TEquals("oauth", data.info.authenticated);

    // check if the delegated user Joe can access fdmanana's database
    // before his name or roles are added to that database's security
    // object - shouldn't be possible

    xhr = oauthRequest(
      "GET", "http://" + host + "/" + encDbPath("fdmanana", "test_db"),
      joe_oauth_msg, joe_oauth_accessor);
    TEquals(401, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals("unauthorized", data.error);

    // now user fdmanana adds delegated user joe to the security object
    var sec_obj = {
      admins: {
        names: ["fdmanana"]
      },
      readers: {
        names: ["joe.delegated.test_db"]
      }
    };
    xhr = oauthRequest(
      "PUT", "http://" + host + "/" + encDbPath("fdmanana", "test_db") +
        "/_security",
      oauth_msg, oauth_accessor, JSON.stringify(sec_obj));
    TEquals(200, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals(true, data.ok);

    // joe should now be able to access the database
    xhr = oauthRequest(
      "GET", "http://" + host + "/" + encDbPath("fdmanana", "test_db"),
      joe_oauth_msg, joe_oauth_accessor);
    TEquals(200, xhr.status);

    xhr = oauthRequest(
      "GET", "http://" + host + "/" + encDbPath("fdmanana", "test_db") + "/doc1",
      joe_oauth_msg, joe_oauth_accessor);
    TEquals(200, xhr.status);
    var doc_copy = JSON.parse(xhr.responseText);
    TEquals(111, doc_copy.value);

    var new_doc = {
      _id: "joe_doc",
      value: 666
    };
    xhr = oauthRequest(
      "PUT", "http://" + host + "/" + encDbPath("fdmanana", "test_db") +
        "/" + new_doc._id,
      joe_oauth_msg, joe_oauth_accessor, JSON.stringify(new_doc));
    TEquals(201, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals(true, data.ok);

    // unless added to the admins of fdmanana's database security object,
    // joe can't write design documents to it
    new_doc = {
      _id: "_design/joe",
      value: "ddoc"
    };
    xhr = oauthRequest(
      "PUT", "http://" + host + "/" + encDbPath("fdmanana", "test_db") +
        "/" + new_doc._id,
      joe_oauth_msg, joe_oauth_accessor, JSON.stringify(new_doc));
    TEquals(401, xhr.status);

    // now add one of joe's roles into the security object of the database
    sec_obj.admins.roles = ["qwerty", "cooker.delegated.test_db"];
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
      joe_oauth_msg, joe_oauth_accessor, JSON.stringify(new_doc));
    TEquals(201, xhr.status);
    data = JSON.parse(xhr.responseText);
    TEquals(true, data.ok);
  }


  usersDb.deleteDb();
  run_on_modified_server(server_config, delegateTestFun);

  // cleanup
  usersDb.deleteDb();
  (new CouchDB(dbPath("fdmanana", "test_db"))).deleteDb();

};
