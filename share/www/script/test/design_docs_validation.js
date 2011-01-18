// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

couchTests.design_docs_validation = function(debug) {

  if (debug) debugger;

  var dbA = new CouchDB("test_suite_db_a", {"X-Couch-Full-Commit": "false"});
  var dbB = new CouchDB("test_suite_db_b", {"X-Couch-Full-Commit": "false"});
  var authDb = new CouchDB("test_suite_users", {"X-Couch-Full-Commit":"false"});
  var server_config = [
    {
      section: "couch_httpd_auth",
      key: "authentication_db",
      value: authDb.name
    },
    {
      section: "couchdb",
      key: "validate_design_docs",
      value: "true"
    }
  ];


  function testFun() {
    dbA.deleteDb();
    dbA.createDb();
    dbB.deleteDb();
    dbB.createDb();

    var doc1 = {
      _id: "foo1",
      value: 1
    };

    var ddoc1 = {
      _id: "_design/ddoc1",
      language: "javascript",
      value: "foo"
    };

    var ddoc2 = {
      _id: "_design/ddoc2",
      language: "javascript",
      validate_doc_update: (function(newDoc, oldDoc, userCtx, secObj) {
        if (newDoc._id.indexOf("_design/") === 0) {
          if (oldDoc) {
            throw {unauthorized: "can not update existing design docs"};
          }
        }
      }).toString()
    };

    T(dbA.save(doc1).ok);
    T(dbA.save(ddoc1).ok);
    T(dbA.save(ddoc2).ok);

    var repResult = CouchDB.replicate(dbA.name, dbB.name);
    T(repResult.ok);
    T(repResult.history[0].docs_written === 3);
    T(repResult.history[0].docs_read === 3);
    T(repResult.history[0].doc_write_failures === 0);

    var copy = dbB.open(doc1._id);
    T(copy !== null);

    copy = dbB.open(ddoc1._id);
    T(copy !== null);

    copy = dbB.open(ddoc2._id);
    T(copy !== null);

    var doc2 = {
      _id: "foo2",
      value: 2
    };

    T(dbA.save(doc2).ok);

    var ddoc3 = {
      _id: "_design/ddoc3",
      language: "javascript",
      value: 666
    };

    T(dbA.save(ddoc3).ok);

    var ddoc1_first_rev = ddoc1._rev;
    ddoc1.value = "bar";
    T(dbA.save(ddoc1).ok);

    var fdmanana = CouchDB.prepareUserDoc({
      name: "fdmanana",
      roles: ["dev"]
    }, "qwerty");

    T(authDb.save(fdmanana).ok);

    T(CouchDB.login("fdmanana", "qwerty").ok);
    T(CouchDB.session().userCtx.name === "fdmanana");
    T(CouchDB.session().userCtx.roles.length === 1);
    T(CouchDB.session().userCtx.roles[0] === "dev");

    repResult = CouchDB.replicate(dbA.name, dbB.name);

    CouchDB.logout();

    T(repResult.ok);
    T(repResult.history[0].docs_written === 2);
    T(repResult.history[0].docs_read === 3);
    T(repResult.history[0].doc_write_failures === 1);

    copy = dbB.open(doc2._id);
    T(copy !== null);

    copy = dbB.open(ddoc3._id);
    T(copy !== null);

    copy = dbB.open(ddoc1._id);
    T(copy !== null);
    // updated ddoc is not replicated
    T(copy._rev === ddoc1_first_rev);
    T(copy.value === "foo");
  }


  authDb.deleteDb();

  run_on_modified_server(server_config, testFun);

  // cleanup
  dbA.deleteDb();
  dbB.deleteDb();
  authDb.deleteDb();
};
