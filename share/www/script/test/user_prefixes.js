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

couchTests.user_prefixes = function(debug) {

  if (debug) debugger;

  var authDb = new CouchDB("test_suite_users", {"X-Couch-Full-Commit":"false"});
  var server_config = [
    {
      section: "couch_httpd_auth",
      key: "authentication_db",
      value: authDb.name
    }
  ];


  // computed in Erlang with couch_util:to_hex(couch_util:md5(UserName))
  // (there's no JavaScript MD5 lib shipped with CouchDB)
  var user_hashes = {
    "joe":  "8ff32489f92f33416694be8fdc2d4c22",
    "jack": "4ff9fc6e4e5d5f590c4f2134a8cc96d1"
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


  function testFunWrapper() {
    try {
      testFun();
    }
    finally {
      CouchDB.logout();
    }
  }

  function testFun() {
    var joe = CouchDB.prepareUserDoc({
      name: "joe",
      roles: ["erlanger"]
    }, "functional");

    T(authDb.save(joe).ok);

    var jack = CouchDB.prepareUserDoc({
      name: "jack",
      roles: ["hero"]
    }, "lost");

    T(authDb.save(jack).ok);

    var db, doc, copy;


    // admins can create, update or delete any DB
    db = new CouchDB("test_suite_db");
    db.deleteDb(); // just in case some previous test created it
    T(db.createDb().ok);

    doc = {
      _id: "doc1",
      value: 1
    };

    T(db.save(doc).ok);

    copy = db.open(doc._id);
    T(copy !== null);

    T(db.info().db_name === "test_suite_db");
    T(CouchDB.allDbs().indexOf("test_suite_db") >= 0);
    T(db.deleteDb().ok);


    // non admins can only create, update and delete DBs whose
    // name has a special prefix

    T(CouchDB.login("joe", "functional").ok);

    db = new CouchDB(dbPath("jack", "test_suite_jack_db"));
    try {
      db.createDb();
      T(false, "shouldn't be possible to create other users' DBs");
    } catch (x) {
      T(x.error === "forbidden");
    }

    db = new CouchDB(dbPath("joe", "test_suite_joe_db"));
    try {
      T(db.createDb().ok);
    } catch (x) {
      T(false, "creation of a DB with the right user prefix should succeed");
    }

    doc = {
      _id: "doc1",
      value: 1
    };

    T(db.save(doc).ok);

    copy = db.open(doc._id);
    T(copy !== null);

    T(db.info().db_name === db.name);
    T(CouchDB.allDbs().indexOf(db.name) >= 0);
    T(db.deleteDb().ok);

    // recreate DB, try to delete it with another user
    T(db.createDb().ok);
    var joes_db_name = db.name;

    CouchDB.logout();
    T(CouchDB.login("jack", "lost").ok);

    // can't see other users' DBs
    T(CouchDB.allDbs().indexOf(joes_db_name) === -1);

    // can't delete other users' DBs
    try {
      db.deleteDb();
    } catch (x) {
      T(x.error === "forbidden");
    }

    // can't read from other users' DBs
    try {
      db.open(doc._id);
    } catch (x) {
      T(x.error === "unauthorized");
    }

    // can't write to other users' DBs
    try {
      db.save({_id: "foobar", value: 666});
    } catch (x) {
      T(x.error === "unauthorized");
    }

    CouchDB.logout();
  }


  (new CouchDB(dbPath("joe", "test_suite_joe_db"))).deleteDb();
  authDb.deleteDb();

  run_on_modified_server(server_config, testFunWrapper);

  // cleanup
  (new CouchDB(dbPath("joe", "test_suite_joe_db"))).deleteDb();
  authDb.deleteDb();
}