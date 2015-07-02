// Copyright 2014 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.enterprise.adaptor.documentum;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.*;

import com.google.common.base.Joiner;
import com.google.common.base.Predicate;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Maps;
import com.google.common.collect.Multimap;
import com.google.common.collect.Multimaps;
import com.google.common.collect.TreeMultimap;
import com.google.enterprise.adaptor.Acl;
import com.google.enterprise.adaptor.Acl.InheritanceType;
import com.google.enterprise.adaptor.AdaptorContext;
import com.google.enterprise.adaptor.Config;
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.DocIdEncoder;
import com.google.enterprise.adaptor.DocIdPusher.Record;
import com.google.enterprise.adaptor.GroupPrincipal;
import com.google.enterprise.adaptor.Principal;
import com.google.enterprise.adaptor.Request;
import com.google.enterprise.adaptor.UserPrincipal;
import com.google.enterprise.adaptor.documentum.DocumentumAdaptor.Checkpoint;
import com.documentum.com.IDfClientX;
import com.documentum.fc.client.DfPermit;
import com.documentum.fc.client.IDfACL;
import com.documentum.fc.client.IDfClient;
import com.documentum.fc.client.IDfCollection;
import com.documentum.fc.client.IDfFolder;
import com.documentum.fc.client.IDfGroup;
import com.documentum.fc.client.IDfPermit;
import com.documentum.fc.client.IDfPermitType;
import com.documentum.fc.client.IDfQuery;
import com.documentum.fc.client.IDfSession;
import com.documentum.fc.client.IDfSessionManager;
import com.documentum.fc.client.IDfSysObject;
import com.documentum.fc.client.IDfType;
import com.documentum.fc.client.IDfUser;
import com.documentum.fc.client.IDfVirtualDocument;
import com.documentum.fc.client.IDfVirtualDocumentNode;
import com.documentum.fc.common.DfException;
import com.documentum.fc.common.IDfAttr;
import com.documentum.fc.common.IDfId;
import com.documentum.fc.common.IDfLoginInfo;
import com.documentum.fc.common.IDfTime;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

/** Unit tests for DocumentAdaptor class. */
public class DocumentumAdaptorTest {

  private static final SimpleDateFormat dateFormat =
      new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

  private static final String EPOCH_1970 = "1970-01-01 00:00:00";
  private static final String JAN_1970 = "1970-01-01 02:03:04";
  private static final String FEB_1970 = "1970-02-01 02:03:04";
  private static final String MAR_1970 = "1970-03-01 02:03:04";

  private static final String CREATE_TABLE_ACL = "create table dm_acl "
      + "(r_object_id varchar, r_accessor_name varchar, "
      + "r_accessor_permit int, r_permit_type int, r_is_group boolean)";

  private static final String CREATE_TABLE_AUDITTRAIL_ACL =
      "create table dm_audittrail_acl "
      + "(r_object_id varchar, chronicle_id varchar, audited_obj_id varchar, "
      + "event_name varchar, time_stamp_utc timestamp)";

  private static final String CREATE_TABLE_CABINET = "create table dm_cabinet "
      + "(r_object_id varchar, r_folder_path varchar, object_name varchar)";

  private static final String CREATE_TABLE_FOLDER = "create table dm_folder "
      + "(r_object_id varchar, r_folder_path varchar)";

  private static final String CREATE_TABLE_GROUP = "create table dm_group "
      + "(r_object_id varchar, group_name varchar, group_source varchar, "
      + "groups_names varchar, users_names varchar, r_modify_date timestamp)";

  private static final String CREATE_TABLE_USER = "create table dm_user "
      + "(user_name varchar primary key, user_login_name varchar, "
      + "user_source varchar, user_ldap_dn varchar, r_is_group boolean)";

  private static final String CREATE_TABLE_SYSOBJECT =
      "create table dm_sysobject "
      + "(r_object_id varchar, r_modify_date timestamp, r_object_type varchar, "
      + "object_name varchar, a_content_type varchar, i_folder_id varchar, "
      + "r_is_virtual_doc boolean, "
      // Note: mock_content ia an artifact that stores the content as a string,
      // and mock_object_path is an artifact used to emulate FOLDER predicate,
      // and to assist getObjectByPath.
      + "mock_content varchar, mock_object_path varchar)";

  private JdbcFixture jdbcFixture = new JdbcFixture();

  @Before
  public void setUp() throws Exception {
    jdbcFixture.executeUpdate(CREATE_TABLE_ACL, CREATE_TABLE_AUDITTRAIL_ACL,
        CREATE_TABLE_CABINET, CREATE_TABLE_FOLDER, CREATE_TABLE_GROUP,
        CREATE_TABLE_SYSOBJECT, CREATE_TABLE_USER);
  }

  @After
  public void tearDown() throws Exception {
    jdbcFixture.tearDown();
  }

  private Config getTestAdaptorConfig() {
    return getTestAdaptorConfig(ProxyAdaptorContext.getInstance());
  }

  private Config getTestAdaptorConfig(AdaptorContext context) {
    Config config = context.getConfig();
    config.addKey("documentum.username", "testuser");
    config.addKey("documentum.password", "testpwd");
    config.addKey("documentum.docbaseName", "testdocbase");
    config.addKey("documentum.displayUrlPattern", "http://webtop/drl/{0}");
    config.addKey("documentum.src", "/Folder1/path1");
    config.addKey("documentum.src.separator", ",");
    config.addKey("documentum.excludedAttributes", "foo, bar");
    config.addKey("adaptor.namespace", "globalNS");
    config.addKey("documentum.windowsDomain", "");
    config.addKey("documentum.pushLocalGroupsOnly", "false");
    config.addKey("documentum.cabinetWhereCondition", "");
    return config;
  }

  /**
   * Initialize adaptor using proxy clientX and proxy AdptorContext.
   * Verifies that the proper user is set;
   * @throws DfException if DFC initialization can't establish connection
   * to Documentum repository. 
   */
  @Test
  public void testDfcConnection() throws DfException {
    InitTestProxies proxyCls = new InitTestProxies();
    DocumentumAdaptor adaptor =
        new DocumentumAdaptor(proxyCls.getProxyClientX());
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = getTestAdaptorConfig(context);

    adaptor.init(context);

    assertEquals("testuser", proxyCls.username);
    // MockSensitiveValueDecoder just uppercases the input.
    assertEquals("TESTPWD", proxyCls.password);
    assertEquals("testdocbase", proxyCls.docbaseName);
    assertEquals(1, proxyCls.docbaseLoginInfoMap.size());
    assertEquals(1, proxyCls.docbaseSessionMap.size());

    List<String> expectedMethodCallSequence = Arrays.asList(
        "getLocalClient", "newSessionManager",
        "getLoginInfo", "setIdentity",
        "getSession", "release",
        "getSession", "release"
    );
    assertEquals(expectedMethodCallSequence, proxyCls.methodCallSequence);

    Set<String> expectedMethodCallSet =
        ImmutableSet.of("setUser", "setPassword", "getDFCVersion",
            "getServerVersion", "getObjectByPath");
    assertEquals(expectedMethodCallSet, proxyCls.methodCalls);
  }

  @Test
  public void testInitStartPaths() throws DfException {
    InitTestProxies proxyCls = new InitTestProxies();
    DocumentumAdaptor adaptor =
        new DocumentumAdaptor(proxyCls.getProxyClientX());
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = getTestAdaptorConfig(context);
    config.overrideKey("documentum.src", "/Folder1/path1, /Folder2/path2,"
        + "/Folder3/path3");
    adaptor.init(context);

    assertEquals(Arrays.asList("/Folder1/path1", "/Folder2/path2",
        "/Folder3/path3"), adaptor.getStartPaths());
  }

  private class InitTestProxies {
    List <String> methodCallSequence = new ArrayList<String>();
    Set <String> methodCalls = new HashSet<String>();

    IDfClient client = getProxyClient();
    IDfLoginInfo loginInfo = getProxyLoginInfo();
    IDfSessionManager sessionManager = getProxySessionManager();

    Map<String, IDfLoginInfo> docbaseLoginInfoMap =
        new HashMap<String, IDfLoginInfo>();
    Map<String, IDfSession> docbaseSessionMap =
        new HashMap<String, IDfSession>();

    Map<String, String> folderPathIdsMap = new HashMap<String, String>() {
      {
        put("/Folder1/path1", "0b01081f80078d2a");
        put("/Folder2/path2", "0b01081f80078d29");
        put("/Folder3/path3", "0b01081f80078d28");
        put("/Folder1/path1,/Folder2/path2,/Folder3/path3,/Folder4/path4",
            "0b01081f80078d2b");
      }
    };

    String username;
    String password;
    String docbaseName;

    public IDfClientX getProxyClientX() {
      return Proxies.newProxyInstance(IDfClientX.class, new ClientXMock());
    }

    private class ClientXMock {
      public String getDFCVersion() {
        methodCalls.add(Proxies.getMethodName());
        return "1.0.0.000 (Mock DFC)";
      }

      public IDfClient getLocalClient() {
        methodCallSequence.add(Proxies.getMethodName());
        return client;
      }

      public IDfLoginInfo getLoginInfo() {
        methodCallSequence.add(Proxies.getMethodName());
        return loginInfo;
      }
    }

    public IDfClient getProxyClient() {
      return Proxies.newProxyInstance(IDfClient.class, new ClientMock());
    }

    private class ClientMock {
      public IDfSessionManager newSessionManager() {
        methodCallSequence.add(Proxies.getMethodName());
        return sessionManager;
      }
    }

    public IDfLoginInfo getProxyLoginInfo() {
      return Proxies.newProxyInstance(IDfLoginInfo.class, new LoginInfoMock());
    }

    private class LoginInfoMock {
      public void setPassword(String password) {
        methodCalls.add(Proxies.getMethodName());
        InitTestProxies.this.password = password;
      }

      public void setUser(String username) {
        methodCalls.add(Proxies.getMethodName());
        InitTestProxies.this.username = username;
      }
    }

    public IDfSessionManager getProxySessionManager() {
      return Proxies.newProxyInstance(IDfSessionManager.class,
          new SessionManagerMock());
    }

    private class SessionManagerMock {
      public IDfSession getSession(String docbaseName) {
        methodCallSequence.add(Proxies.getMethodName());
        IDfSession session = docbaseSessionMap.get(docbaseName);
        if (session == null) {
          session =
              Proxies.newProxyInstance(IDfSession.class, new SessionMock());
          docbaseSessionMap.put(docbaseName, session);
        }
        return session;
      }

      public void release(IDfSession session) {
        methodCallSequence.add(Proxies.getMethodName());
        // TODO(sveldurthi): remove from the map to release the session
      }

      public void setIdentity(String docbaseName, IDfLoginInfo loginInfo) {
        methodCallSequence.add(Proxies.getMethodName());
        InitTestProxies.this.docbaseName = docbaseName;
        docbaseLoginInfoMap.put(docbaseName, loginInfo);
      }
    }

    private class SessionMock {
      public String getServerVersion() {
        methodCalls.add(Proxies.getMethodName());
        return "1.0.0.000 (Mock CS)";
      }

      public IDfSysObject getObjectByPath(String path) {
        methodCalls.add(Proxies.getMethodName());
        if (folderPathIdsMap.containsKey(path)) {
          return Proxies.newProxyInstance(IDfSysObject.class,
              new SysObjectMock(path));
        } else {
          return null;
        }
      }
    }

    private class SysObjectMock {
      private String objectPath;

      public SysObjectMock(String objectPath) {
        this.objectPath = objectPath;
      }

      public IDfId getObjectId() {
        String id = folderPathIdsMap.get(objectPath);
        return Proxies.newProxyInstance(IDfId.class, new IdMock(id));
      }
    }

    private class IdMock {
      private String objectId;

      public IdMock(String objectId) {
        this.objectId = objectId;
      }

      public String toString() {
        return objectId;
      }
    }
  }

  @Test
  public void testParseStartPaths() {
    String path1 = "Folder1/path1";
    String path2 = "Folder2/path2";
    String path3 = "Folder3/path3";
    String startPaths = path1 + "," + path2 + "," + path3;

    List<String> paths = DocumentumAdaptor.parseStartPaths(startPaths, ",");
    assertEquals(ImmutableList.of(path1, path2, path3), paths);
  }

  @Test
  public void testParseStartPathsSeperator() {
    String path1 = "Folder1/path1";
    String path2 = "Folder2/path2";
    String path3 = "Folder3/path3";
    String separator = ":";
    String startPaths = path1 + separator + path2 + separator + path3;

    List<String> paths =
        DocumentumAdaptor.parseStartPaths(startPaths, separator);
    assertEquals(ImmutableList.of(path1, path2, path3), paths);
  }

  @Test
  public void testParseStartPathsNotUsingRegExSeparator() {
    String path1 = "Folder1/path1";
    String path2 = "Folder2/path2";
    String path3 = "Folder3/path3";

    String startPaths = path1 + ";" + path2 + ":" + path3 + ",";
    List<String> paths = DocumentumAdaptor.parseStartPaths(startPaths, "[:;,]");
    assertEquals(ImmutableList.of(startPaths), paths);

    startPaths = path1 + "[:;,]" + path2 + "[:;,]" + path3 + "[:;,]";
    paths = DocumentumAdaptor.parseStartPaths(startPaths, "[:;,]");
    assertEquals(ImmutableList.of(path1, path2, path3), paths);
  }

  @Test
  public void testParseStartPathsBlankSeparator() {
    String path1 = "Folder1/path1";
    String path2 = "Folder2/path2";
    String path3 = "Folder3/path3";
    String startPaths = path1 + "," + path2 + "," + path3;

    List<String> paths = DocumentumAdaptor.parseStartPaths(startPaths, "");
    assertEquals(ImmutableList.of(startPaths), paths);
  }

  @Test
  public void testParseStartPathsSinglePath() {
    String path1 = "Folder1/path1";
    String startPaths = path1;

    List<String> paths = DocumentumAdaptor.parseStartPaths(startPaths, ",");
    assertEquals(ImmutableList.of(path1), paths);
  }

  @Test
  public void testParseStartPathsEmptyPath() {
    String path1 = "Folder1/path1";
    String path2 = "Folder2/path2";
    String path3 = "";
    String startPaths = path1 + "," + path2 + "," + path3;

    List<String> paths = DocumentumAdaptor.parseStartPaths(startPaths, ",");
    assertEquals(ImmutableList.of(path1, path2), paths);
  }

  @Test
  public void testParseStartPathsWhiteSpacePath() {
    String path1 = "Folder 1/path 1";
    String path2 = " Folder 2/path 2 ";
    String path3 = "Folder 3/ path 3 ";
    String startPaths = path1 + "," + path2 + "," + path3;

    List<String> paths = DocumentumAdaptor.parseStartPaths(startPaths, ",");
    assertEquals(ImmutableList.of(path1.trim(), path2.trim(), path3.trim()),
        paths);
  }

  @Test
  public void testSlashAsStartPath() throws Exception {
    String root = "/";
    DocId docid = DocumentumAdaptor.docIdFromPath(root);
    assertEquals(root, DocumentumAdaptor.docIdToPath(docid));
    assertEquals("/foo", DocumentumAdaptor.docIdToPath(
        DocumentumAdaptor.docIdFromPath(root, "foo")));
    
  }

  private void initializeAdaptor(DocumentumAdaptor adaptor, String src,
      String separator) throws DfException {
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = context.getConfig();

    adaptor.initConfig(config);

    config.overrideKey("documentum.username", "testuser");
    config.overrideKey("documentum.password", "testpwd");
    config.overrideKey("documentum.docbaseName", "testdocbase");
    config.overrideKey("documentum.displayUrlPattern",
        "http://webtopurl/drl/{0}");
    config.overrideKey("documentum.src", src);
    if (separator != null) {
      config.overrideKey("documentum.src.separator", separator);
    }

    adaptor.init(context);
  }

  @Test
  public void testConfigSeparator() throws DfException {
    DocumentumAdaptor adaptor =
        new DocumentumAdaptor(new InitTestProxies().getProxyClientX());
    String path1 = "/Folder1/path1";
    String path2 = "/Folder2/path2";
    String path3 = "/Folder3/path3";
    String path4 = "/Folder4/path4";
    String startPaths = path1 + ";" + path2 + ";" + path3 + ";" + path4;

    initializeAdaptor(adaptor, startPaths, ";");

    assertEquals(ImmutableList.of(path1, path2, path3, path4),
        adaptor.getStartPaths());
  }

  @Test
  public void testConfigBlankSeparatorValue() throws DfException {
    DocumentumAdaptor adaptor =
        new DocumentumAdaptor(new InitTestProxies().getProxyClientX());
    String path1 = "/Folder1/path1";
    String path2 = "/Folder2/path2";
    String path3 = "/Folder3/path3";
    String path4 = "/Folder4/path4";
    String startPaths = path1 + "," + path2 + "," + path3 + "," + path4;

    initializeAdaptor(adaptor, startPaths, "");

    assertEquals(ImmutableList.of(startPaths), adaptor.getStartPaths());
  }

  @Test
  public void testConfigNoSeparatorEntry() throws DfException {
    DocumentumAdaptor adaptor =
        new DocumentumAdaptor(new InitTestProxies().getProxyClientX());
    String path1 = "/Folder1/path1";
    String path2 = "/Folder2/path2";
    String path3 = "/Folder3/path3";
    String path4 = "/Folder4/path4";
    String startPaths = path1 + "," + path2 + "," + path3 + "," + path4;

    initializeAdaptor(adaptor, startPaths, null);

    assertEquals(ImmutableList.of(path1, path2, path3, path4),
        adaptor.getStartPaths());
  }

  private void initValidStartPaths(DocumentumAdaptor adaptor,
      String... paths) throws DfException {
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = getTestAdaptorConfig(context);
    String startPaths = paths[0];
    for (int i = 1; i < paths.length; i++) {
      startPaths = startPaths + "," + paths[i];
    }
    config.overrideKey("documentum.src", startPaths);

    adaptor.init(context);
  }

  @Test
  public void testValidateStartPathsRootPath() throws DfException {
    DocumentumAdaptor adaptor =
        new DocumentumAdaptor(new InitTestProxies().getProxyClientX());

    String path1 = "/";

    initValidStartPaths(adaptor, path1);
    assertEquals(ImmutableList.of(path1), adaptor.getValidatedStartPaths());
  }

  @Test
  public void testValidateStartPathsAllValid() throws DfException {
    DocumentumAdaptor adaptor =
        new DocumentumAdaptor(new InitTestProxies().getProxyClientX());

    String path1 = "/Folder1/path1";
    String path2 = "/Folder2/path2";
    String path3 = "/Folder3/path3";

    initValidStartPaths(adaptor, path1, path2, path3);
    assertEquals(ImmutableList.of(path1, path2, path3),
        adaptor.getValidatedStartPaths());
  }

  @Test
  public void testValidateStartPathsSomeValid() throws DfException {
    DocumentumAdaptor adaptor =
        new DocumentumAdaptor(new InitTestProxies().getProxyClientX());

    String path1 = "/Folder1/path1";
    String path2 = "/Folder2/path2";
    String path3 = "/Folder4/path3";
    String path4 = "/Folder4/path4";

    initValidStartPaths(adaptor, path1, path2, path3, path4);
    assertEquals(ImmutableList.of(path1, path2),
        adaptor.getValidatedStartPaths());
  }

  @Test
  public void testValidateStartPathsSomeInvalid() throws DfException {
    DocumentumAdaptor adaptor =
        new DocumentumAdaptor(new InitTestProxies().getProxyClientX());

    String path1 = "/Folder4/path4";
    String path2 = "/Folder5/path5";
    String path3 = "/Folder1/path1";
    String path4 = "/Folder2/path2";

    initValidStartPaths(adaptor, path1, path2, path3, path4);
    assertEquals(ImmutableList.of(path3, path4),
        adaptor.getValidatedStartPaths());
  }

  @Test
  public void testValidateStartPathsNormalizePaths() throws DfException {
    DocumentumAdaptor adaptor =
        new DocumentumAdaptor(new InitTestProxies().getProxyClientX());

    String path1 = "/Folder1/path1/";
    String path2 = "Folder2/path2";
    String path3 = "Folder3/path3/";
    String path4 = "Folder5/path5";

    initValidStartPaths(adaptor, path1, path2, path3, path4);
    assertEquals(ImmutableList.of("/Folder1/path1", "/Folder2/path2",
       "/Folder3/path3"), adaptor.getValidatedStartPaths());
  }

  @Test(expected = IllegalStateException.class)
  public void testValidateStartPathsNoneValid() throws DfException {
    DocumentumAdaptor adaptor =
        new DocumentumAdaptor(new InitTestProxies().getProxyClientX());

    String path1 = "/Folder1/path4";
    String path2 = "/Folder2/path5";
    String path3 = "/Folder3/path6";

    initValidStartPaths(adaptor, path1, path2, path3);
  }

  private void insertCabinets(String... cabinets) throws SQLException {
    for (String cabinet : cabinets) {
      jdbcFixture.executeUpdate(String.format("INSERT INTO dm_cabinet "
          + "(r_object_id, r_folder_path, object_name) VALUES('%s','%s','%s')",
          "0c" + cabinet, "/" + cabinet, cabinet));
    }
  }

  private void checkGetRootContent(String whereClause, int maxHtmlLinks,
      String... expectedCabinets) throws Exception {
    H2BackedTestProxies proxyCls = new H2BackedTestProxies();
    IDfClientX dmClientX = proxyCls.getProxyClientX();
    DocumentumAdaptor adaptor = new DocumentumAdaptor(dmClientX);
    DocIdEncoder docidEncoder =
        ProxyAdaptorContext.getInstance().getDocIdEncoder();
    MockRequest request = new MockRequest(adaptor.docIdFromPath("/"));
    MockResponse response = new MockResponse();

    List<String> queries = new ArrayList<>();
    Logging.captureLogMessages(DocumentumAdaptor.class,
        "Get All Cabinets Query", queries);

    adaptor.getDocContentHelper(request, response, dmClientX, 
        proxyCls.sessionManager, docidEncoder, ImmutableList.of("/"),
        null, whereClause, maxHtmlLinks, "");

    assertEquals(queries.toString(), 1, queries.size());
    String query = queries.get(0); 
    if (whereClause.isEmpty()) {
      assertFalse(query, query.contains(" WHERE "));
    } else {
      assertTrue(query, query.contains(" WHERE " + whereClause));
    }

    assertEquals("text/html; charset=UTF-8", response.contentType);
    String content = response.content.toString(UTF_8.name());

    assertEquals(content, maxHtmlLinks == 0 || expectedCabinets.length == 0,
                 content.indexOf("href") < 0);
    assertEquals(response.anchors.toString(),
                 maxHtmlLinks >= expectedCabinets.length,
                 response.anchors.isEmpty());

    for (String cabinet : expectedCabinets) {
      // First look in the HTML links for the cabinet. If not there,
      // look in the external anchors.
      String link = "<a href=\"" + cabinet + "\">" + cabinet + "</a>";
      if (content.indexOf(link) < 0) {
        URI uri = docidEncoder.encodeDocId(new DocId(cabinet));
        URI anchor = response.anchors.get(cabinet);
        assertNotNull("Cabinet " + cabinet + " with URI " + uri + " is missing"
            + " from response:/n" + content + "/n" + response.anchors, anchor);
        assertEquals(uri, anchor);
      }
    }
  }

  @Test
  public void testGetRootContentNoCabinets() throws Exception {
    checkGetRootContent("1=1", 100);
  }

  @Test
  public void testGetRootContentEmptyWhereClause() throws Exception {
    insertCabinets("System", "Cabinet1", "Cabinet2");
    checkGetRootContent("", 100, "System", "Cabinet1", "Cabinet2");
  }

  @Test
  public void testGetRootContentHtmlResponseOnly() throws Exception {
    insertCabinets("Cabinet1", "Cabinet2", "Cabinet3");
    checkGetRootContent("", 100, "Cabinet1", "Cabinet2", "Cabinet3");
  }

  @Test
  public void testGetRootContentAnchorResponseOnly() throws Exception {
    insertCabinets("Cabinet1", "Cabinet2", "Cabinet3");
    checkGetRootContent("", 0, "Cabinet1", "Cabinet2", "Cabinet3");
  }

  @Test
  public void testGetRootContentHtmlAndAnchorResponse() throws Exception {
    insertCabinets("Cabinet1", "Cabinet2", "Cabinet3", "Cabinet4");
    checkGetRootContent("", 2, "Cabinet1", "Cabinet2", "Cabinet3",
       "Cabinet4");
  }

  @Test
  public void testGetRootContentAddedWhereClause() throws Exception {
    insertCabinets("System", "Temp", "Cabinet1", "Cabinet2");
    checkGetRootContent("object_name NOT IN ('System', 'Temp')",
        100, "Cabinet1", "Cabinet2");
  }

  @Test
  public void testGetRootContentDefaultWhereClause() throws Exception {
    jdbcFixture.executeUpdate(
        "CREATE TABLE dm_docbase_config (owner_name varchar)",
        "INSERT INTO dm_docbase_config (owner_name) VALUES('Owner')",
        "CREATE TABLE dm_server_config (r_install_owner varchar)",
        "INSERT INTO dm_server_config (r_install_owner) VALUES('Installer')");
    insertCabinets("Integration", "Resources", "System");
    insertCabinets("Temp", "Templates", "Owner", "Installer");
    insertCabinets("Cabinet1", "Cabinet2");

    Config config = ProxyAdaptorContext.getInstance().getConfig();
    new DocumentumAdaptor(null).initConfig(config);

    checkGetRootContent(config.getValue("documentum.cabinetWhereCondition"),
        100, "Cabinet1", "Cabinet2");
  }

  @Test
  public void testGetRootContentInvalidWhereClause() throws Exception {
    insertCabinets("Cabinet1", "Cabinet2");
    try {
      checkGetRootContent("( xyzzy", 100);
      fail("Expected exception not thrown.");
    } catch (IOException expected) {
      assertTrue(expected.getCause() instanceof DfException);
    }
  }

  /* Mock proxy classes for testing file content */
  private class DocContentTestProxies {

    public IDfClientX getProxyClientX() {
      return Proxies.newProxyInstance(IDfClientX.class, new ClientXMock());
    }

    private class ClientXMock {
    }

    public IDfSessionManager getProxySessionManager() {
      return Proxies.newProxyInstance(IDfSessionManager.class,
          new SessionManagerMock());
    }

    private class SessionManagerMock {
      public IDfSession getSession(String docbaseName) {
        return Proxies.newProxyInstance(IDfSession.class, new SessionMock());
      }
    }

    private class SessionMock {
      public IDfSysObject getObjectByPath(String path) throws DfException {
        String query = String.format("SELECT * FROM dm_sysobject "
            + "WHERE mock_object_path = '%s'", path);
        try (Statement stmt = jdbcFixture.getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
          if (rs.first()) {
            if (rs.getString("r_object_type").startsWith("dm_folder")) {
              return Proxies.newProxyInstance(IDfFolder.class,
                  new FolderMock(rs));
            } else {
              return Proxies.newProxyInstance(IDfSysObject.class,
                  new SysObjectMock(rs));
            }
          }
          return null;
        } catch (SQLException e) {
          throw new DfException(e);
        }
      }
    }

    private class SysObjectMock {
      private final String id;
      private final String name;
      private final String type;
      private final String contentType;
      private final String content;
      private final Date lastModified;
      private final boolean isVirtualDocument;
      private final Multimap<String, String> attributes;

      public SysObjectMock(ResultSet rs) throws SQLException {
        id = rs.getString("r_object_id");
        name = rs.getString("object_name");
        type = rs.getString("r_object_type");
        contentType = rs.getString("a_content_type");
        content = rs.getString("mock_content");
        lastModified = new Date(rs.getTimestamp("r_modify_date").getTime());
        isVirtualDocument = rs.getBoolean("r_is_virtual_doc");
        attributes = readAttributes(id);
      }

      public IDfId getObjectId() {
        return Proxies.newProxyInstance(IDfId.class, new IdMock(id));
      }

      public String getObjectName() {
        return name;
      }

      public String getString(String attrName) {
        switch (attrName) {
          case "object_name": return name;
          case "r_object_id": return id;
          default: return null;
        }
      }

      public InputStream getContent() {
        if (content == null) {
          return null;
        }
        return new ByteArrayInputStream(content.getBytes(UTF_8));
      }

      public IDfType getType() {
        return Proxies.newProxyInstance(IDfType.class, new TypeMock(type));
      }

      public String getContentType() {
        return contentType;
      }

      public IDfTime getTime(String attr) {
        if (attr.equals("r_modify_date")) {
          return Proxies.newProxyInstance(IDfTime.class,
              new TimeMock(lastModified));
        } else {
          return null;
        }
      }

      public boolean isVirtualDocument() {
        return isVirtualDocument;
      }

      public IDfVirtualDocument asVirtualDocument(String lateBinding,
          boolean followRootAssembly) {
        return Proxies.newProxyInstance(IDfVirtualDocument.class,
            new VirtualDocumentMock(id));
      }

      public Enumeration<IDfAttr> enumAttrs() throws DfException {
        Vector<IDfAttr> v = new Vector<IDfAttr>();
        for (String name : attributes.keySet()) {
          v.add(Proxies.newProxyInstance(IDfAttr.class, new AttrMock(name)));
        }
        return v.elements();
      }

      public int getValueCount(String name) {
        return attributes.get(name).size();
      }

      public String getRepeatingString(String name, int index) {
        return new ArrayList<String>(attributes.get(name)).get(index);
      }
    }

    private class VirtualDocumentMock {
      private final String vdocId;
      
      public VirtualDocumentMock(String vdocId) {
        this.vdocId = vdocId;
      }

      public IDfVirtualDocumentNode getRootNode() throws DfException {
        return Proxies.newProxyInstance(IDfVirtualDocumentNode.class,
            new VdocRootNodeMock(vdocId));
      }
    }

    private class VdocRootNodeMock {
      private final ArrayList<String> vdocChildren = new ArrayList<>();

      public VdocRootNodeMock(String vdocId) throws DfException {
        String query = String.format("SELECT mock_object_path "
            + "FROM dm_sysobject WHERE i_folder_id = '%s'", vdocId);
        try (Statement stmt = jdbcFixture.getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
          while (rs.next()) {
            vdocChildren.add(rs.getString("mock_object_path"));
          }
        } catch (SQLException e) {
          throw new DfException(e);
        }
      }

      public int getChildCount() {
        return vdocChildren.size();
      }

      public IDfVirtualDocumentNode getChild(int index) {
        return Proxies.newProxyInstance(IDfVirtualDocumentNode.class,
            new VdocChildNodeMock(vdocChildren.get(index)));
      }
    }

    private class VdocChildNodeMock {
      private final String childPath;

      public VdocChildNodeMock(String childPath) {
        this.childPath = childPath;
      }

      public IDfSysObject getSelectedObject() throws DfException {
        IDfSession session = DocContentTestProxies.this
            .getProxySessionManager().getSession("foo");
        return (IDfSysObject) session.getObjectByPath(childPath);
      }
    }

    private class FolderMock extends SysObjectMock {
      public FolderMock(ResultSet rs) throws SQLException {
        super(rs);
      }

      public IDfCollection getContents(String colNames) throws DfException {
        String query = String.format(
            "SELECT %s FROM dm_sysobject WHERE i_folder_id = '%s'",
            colNames, getObjectId());
        return Proxies.newProxyInstance(IDfCollection.class,
            new CollectionMock(query));
      }
    }
      
    private class CollectionMock {
      private final Statement stmt;
      private final ResultSet rs;

      public CollectionMock(String query) throws DfException {
        try {
          stmt = jdbcFixture.getConnection().createStatement();
          rs = stmt.executeQuery(query);
        } catch (SQLException e) {
          throw new DfException(e);
        }
      }

      public String getString(String colName) throws DfException {
        try {
          return rs.getString(colName);
        } catch (SQLException e) {
          throw new DfException(e);
        }
      }

      public boolean next() throws DfException {
        try {
          return rs.next();
        } catch (SQLException e) {
          throw new DfException(e);
        }
      }

      public void close() throws DfException {
        try {
          rs.close();
          stmt.close();
        } catch (SQLException e) {
          throw new DfException(e);
        }
      }
    }

    private class TypeMock {
      private final String type;

      public TypeMock(String type) {
        this.type = type;
      }

      public boolean isTypeOf(String otherType) {
        return type.startsWith(otherType);
      }

      public String getName() {
        return type;
      }
    }

    private class TimeMock {
      private final Date date;

      public TimeMock(Date date) {
        this.date = date;
      }

      public Date getDate() {
        return date;
      }
    }

    private class IdMock {
      private final String objectId;

      public IdMock(String objectId) {
        this.objectId = objectId;
      }

      public String toString() {
        return objectId;
      }
    }

    private class AttrMock {
      private final String name;

      public AttrMock(String name) {
        this.name = name;
      }

      public String getName() {
        return name;
      }
    }
  }

  @Test
  public void testDocContentInitialCrawl() throws Exception {
    Date lastModified = new Date();
    testDocContent(null, lastModified, false);
  }

  @Test
  public void testDocContentModifiedSinceLastCrawl() throws Exception {
    Date lastCrawled = new Date();
    Date lastModified = new Date(lastCrawled.getTime() + (120 * 1000L));
    testDocContent(lastCrawled, lastModified, false);
  }

  @Test
  public void testDocContentOneDayBeforeWindowJustShort() throws Exception {
    Date lastCrawled = new Date();
    Date lastModified = new Date( // Two seconds short of a full day.
        lastCrawled.getTime() - (24 * 60 * 60 * 1000L - 2000L));
    testDocContent(lastCrawled, lastModified, false);
  }

  @Test
  public void testDocContentOneDayBeforeWindowJustOver() throws Exception {
    Date lastCrawled = new Date();
    Date lastModified = new Date( // Two seconds more than a full day.
        lastCrawled.getTime() - (24 * 60 * 60 * 1000L + 2000L));
    testDocContent(lastCrawled, lastModified, true);
  }

  @Test
  public void testDocContentRecentlyModified() throws Exception {
    // Even though content was crawled after it was recently
    // modified, don't trust Documentum dates to be UTC, so
    // content should be returned anyway.
    Date lastCrawled = new Date();
    Date lastModified = new Date(lastCrawled.getTime() - (8 * 60 * 60 * 1000L));
    testDocContent(lastModified, lastCrawled, false);
  }

  @Test
  public void testDocContentNotRecentlyModified() throws Exception {
    Date lastCrawled = new Date();
    Date lastModified =
        new Date(lastCrawled.getTime() - (72 * 60 * 60 * 1000L));
    testDocContent(lastCrawled, lastModified, true);
  }

  private void insertDocument(String path) throws SQLException {
    insertDocument(new Date(), path, "text/plain", "Hello World");
  }

  private void insertDocument(Date lastModified, String path,
       String contentType, String content) throws SQLException {
    String name = path.substring(path.lastIndexOf("/") + 1);
    jdbcFixture.executeUpdate(String.format(
        "insert into dm_sysobject(r_object_id, object_name, mock_object_path, "
        + "r_object_type, a_content_type, mock_content, r_modify_date) "
        + "values('%s', '%s', '%s', '%s', '%s', '%s', {ts '%s'})",
        "09" + name, name, path, "dm_document", contentType, content,
        dateFormat.format(lastModified)));
  }

  private void testDocContent(Date lastCrawled, Date lastModified,
      boolean expectNotModified) throws Exception {
    String path = "/Folder1/path1/object1";
    String contentType = "crtext/html";
    String content = "<html><body>Hello</body></html>";
    insertDocument(lastModified, path, contentType, content);

    Request request = new MockRequest(DocumentumAdaptor.docIdFromPath(path),
        lastCrawled);
    MockResponse response = getDocContent(request, "", null, "/Folder1");

    if (expectNotModified) {
      assertTrue(response.notModified);
      assertNull(response.contentType);
      assertNull(response.content);
    } else {
      assertFalse(response.notModified);
      assertEquals(contentType, response.contentType);
      assertEquals(content, response.content.toString(UTF_8.name()));
    }
  }

  @Test
  public void testDisplayUrlWithId() throws Exception {
    String path = "/Folder1/path1/object1";
    assertEquals("http://webtopurl/drl/09object1",
        getDisplayUrl("http://webtopurl/drl/{0}", path));
  }

  @Test
  public void testDisplayUrlWithPath() throws Exception {
    String path = "/Folder1/path1/object1";
    assertEquals("http://webtopurl/drl//Folder1/path1/object1",
        getDisplayUrl("http://webtopurl/drl/{1}", path));
  }

  @Test
  public void testDisplayUrlWithIdAndPath() throws Exception {
    String path = "/Folder1/path1/object1";
    assertEquals("/Folder1/path1/object1-http://webtopurl/09object1/drl/",
        getDisplayUrl("{1}-http://webtopurl/{0}/drl/", path));
  }

  @Test
  public void testDisplayUrlNoIdOrPath() throws Exception {
    String path = "/Folder1/path1/object1";
    assertEquals("http://webtopurl/drl",
        getDisplayUrl("http://webtopurl/drl", path));
  }

  private String getDisplayUrl(String displayUrlPattern, String path)
      throws Exception {
    insertDocument(path);
    String startPath = path.substring(0, path.indexOf("/", 1));
    Request request = new MockRequest(DocumentumAdaptor.docIdFromPath(path));
    MockResponse response = getDocContent(request, displayUrlPattern, null,
        startPath);
    return response.displayUrl.toString();
  }

  private MockResponse getDocContent(String path, String... startPaths)
      throws Exception {
    return getDocContent(new MockRequest(DocumentumAdaptor.docIdFromPath(path)),
        "", null, startPaths);
  }

  private MockResponse getDocContent(Request request, String displayUrlPattern,
      Set<String> excludedAttributes, String... startPaths) throws Exception {
    DocContentTestProxies proxyCls = new DocContentTestProxies();
    IDfClientX dmClientX = proxyCls.getProxyClientX();
    IDfSessionManager sessionManager = proxyCls.getProxySessionManager();
    DocumentumAdaptor adaptor = new DocumentumAdaptor(dmClientX);
    MockResponse response = new MockResponse();

    adaptor.getDocContentHelper(request, response, dmClientX, sessionManager,
        ProxyAdaptorContext.getInstance().getDocIdEncoder(),
        Arrays.asList(startPaths), excludedAttributes, null, 1000,
        displayUrlPattern);

    return response;
  }

  @Test
  public void testSingleValueMetadata() throws Exception {
    TreeMultimap<String, String> attributes = TreeMultimap.create();
    attributes.put("attr1", "value1");
    attributes.put("attr2", "value2");
    attributes.put("attr3", "value3");
    testMetadata(attributes, attributes);
  }

  @Test
  public void testMultiValueMetadata() throws Exception {
    TreeMultimap<String, String> attributes = TreeMultimap.create();
    attributes.put("attr1", "value1");
    attributes.put("attr1", "value2");
    attributes.put("attr1", "value3");
    assertEquals(1, attributes.keySet().size());
    assertEquals(3, attributes.get("attr1").size());
    testMetadata(attributes, attributes);
  }

  @Test
  public void testEmptyValueMetadata() throws Exception {
    TreeMultimap<String, String> attributes = TreeMultimap.create();
    attributes.put("attr1", "value1");
    attributes.put("attr2", "value2");
    attributes.put("attr2", "");
    attributes.put("attr3", "");
    testMetadata(attributes, attributes);
  }

  @Test
  public void testExcludeAttrMetadata() throws Exception {
    TreeMultimap<String, String> attributes = TreeMultimap.create();
    attributes.put("attr1", "value1");
    attributes.put("attr2", "value2");
    attributes.put("attr3", "value3");
    attributes.put("foo", "foo1");
    attributes.put("bar", "bar1");
    TreeMultimap<String, String> expected = TreeMultimap.create(attributes);
    expected.removeAll("foo");  // In the excludedAttributes set.
    expected.removeAll("bar");  // In the excludedAttributes set.
    testMetadata(attributes, expected);
  }

  /*
   * Note that the metadata structure stored in these tests is slightly
   * different that Documentum stores them:
   *
   * DCTM stores the data as:
   *
   * attr1    attr2    attr3
   * -----    -----    -----
   * valu1    valuA    valuI
   * valu2             valuII
   * valu3
   * 
   * whereas this table is:
   * 
   * attr1    attr2    attr3
   * -----    -----    -----
   * valu1
   * valu2
   * valu3
   *          valuA
   *                   valuI
   *                   valuII
   *
   * The difference is insignificant for these tests.
   */
  private void writeAttributes(String objectId, Multimap<String, String> attrs)
      throws SQLException {
    StringBuilder ddl = new StringBuilder();
    ddl.append("CREATE TABLE attributes (r_object_id varchar");
    for (String attr : attrs.keySet()) {
      ddl.append(", ").append(attr).append(" varchar");
    }
    ddl.append(")");
    jdbcFixture.executeUpdate(ddl.toString());

    for (String attr : attrs.keySet()) {
      for (String value : attrs.get(attr)) {
        jdbcFixture.executeUpdate(String.format(
            "INSERT INTO attributes (r_object_id, %s) VALUES ('%s', '%s')",
            attr, objectId, value));
      }
    }
  }

  private Multimap<String, String> readAttributes(String objectId)
      throws SQLException {
    Multimap<String, String> attributes = TreeMultimap.create();
    try (Connection connection = jdbcFixture.getConnection()) {
      DatabaseMetaData dbm = connection.getMetaData();
      try (ResultSet tables = dbm.getTables(null, null, "ATTRIBUTES", null)) {
        if (!tables.next()) {
          // Attributes table does not exist if there are
          // no attributes in the test.
          return attributes;
        }
      }
      // Read all the attributes for our objectId.
      String query = String.format("SELECT * FROM attributes "
          + "WHERE r_object_id = '%s'", objectId);
      try (Statement stmt = connection.createStatement();
           ResultSet rs = stmt.executeQuery(query)) {
        ResultSetMetaData rsm = rs.getMetaData();
        while (rs.next()) {
          for (int i = 1; i <= rsm.getColumnCount(); i++) {
            // H2 uppercases the column names.
            String attr = rsm.getColumnName(i).toLowerCase();
            if (!attr.equals("r_object_id")) {
              String value = rs.getString(attr);
              if (value != null) {
                attributes.put(attr, value);
              }
            }
          }
        }
      }
    }
    return attributes;
  }

  private void testMetadata(TreeMultimap<String, String> attrs,
      TreeMultimap<String, String> expected) throws Exception {
    String path = "/Folder1/path1/object1";
    String objectId = "09object1";
    insertDocument(path);
    writeAttributes(objectId, attrs);

    Request request = new MockRequest(DocumentumAdaptor.docIdFromPath(path));
    MockResponse response =
        getDocContent(request, "", ImmutableSet.of("foo", "bar"), "/Folder1");

    assertEquals(expected, response.metadata);
  }

  private void insertVirtualDocument(String vdocPath, String contentType,
      String content, String... children) throws SQLException {
    String name = vdocPath.substring(vdocPath.lastIndexOf("/") + 1);
    String vdocId = "09" + name;
    String now = getNowPlusMinutes(0);
    jdbcFixture.executeUpdate(String.format(
        "INSERT INTO dm_sysobject(r_object_id, object_name, mock_object_path, "
        + "r_object_type, r_is_virtual_doc, a_content_type, mock_content, "
        + "r_modify_date) "
        + "VALUES('%s', '%s', '%s', '%s', TRUE, '%s', '%s', {ts '%s'})",
        vdocId, name, vdocPath, "dm_document_virtual", contentType, content,
        now));
    for (String child : children) {
      insertDocument(now, "09" + child, vdocPath + "/" + child, vdocId);
    }
  }

  @Test
  public void testVirtualDocContentNoChildren() throws Exception {
    String path = "/Folder1/path1/vdoc";
    String objectContentType = "crtext/html";
    String objectContent = "<html><body>Hello</body></html>";
    insertVirtualDocument(path, objectContentType, objectContent);

    MockResponse response = getDocContent(path, "/Folder1");

    assertEquals(objectContentType, response.contentType);
    assertEquals(objectContent, response.content.toString(UTF_8.name()));
    assertTrue(response.anchors.isEmpty());
  }

  @Test
  public void testVirtualDocContentWithChildren() throws Exception {
    String path = "/Folder1/path1/vdoc";
    String objectContentType = "crtext/html";
    String objectContent = "<html><body>Hello</body></html>";
    insertVirtualDocument(path, objectContentType, objectContent,
        "object1", "object2", "object3");

    MockResponse response = getDocContent(path, "/Folder1");

    assertEquals(objectContentType, response.contentType);
    assertEquals(objectContent, response.content.toString(UTF_8.name()));

    // Verify child links.
    assertEquals(3, response.anchors.size());
    for (String name : ImmutableList.of("object1", "object2", "object3")) {
      URI uri = response.anchors.get(name);
      assertNotNull(uri);
      assertTrue(uri.toString().endsWith(path + "/" + name));
    }
  }

  @Test
  public void testFolderDocContent() throws Exception {
    String now = getNowPlusMinutes(0);
    String folderId = "0b01081f80078d29";
    String folder = "/Folder1/subfolder/path2";
    insertFolder(now, folderId, folder);
    insertDocument(now, "0901081f80079263", folder + "/file1", folderId);
    insertDocument(now, "0901081f8007926d", folder + "/file2 evil<chars?",
        folderId);
    insertDocument(now, "0901081f80079278", folder + "/file3", folderId);

    StringBuilder expected = new StringBuilder();
    expected.append("<!DOCTYPE html>\n<html><head><title>");
    expected.append("Folder path2");
    expected.append("</title></head><body><h1>");
    expected.append("Folder path2");
    expected.append("</h1>");
    expected.append("<li><a href=\"path2/file1\">file1</a></li>");
    expected.append("<li><a href=\"path2/file2%20evil%3Cchars%3F\">"
        + "file2 evil&lt;chars?</a></li>");
    expected.append("<li><a href=\"path2/file3\">file3</a></li>");
    expected.append("</body></html>");

    MockResponse response = getDocContent(folder, "/Folder1");

    assertFalse(response.notFound);
    assertEquals("text/html; charset=UTF-8", response.contentType);
    assertEquals(expected.toString(), response.content.toString(UTF_8.name()));
  }

  @Test
  public void testGetDocContentNotFound() throws Exception {
    assertTrue(getDocContent("/Folder1/doesNotExist", "/Folder1").notFound);
  }

  @Test
  public void testGetDocContentNotUnderStartPath() throws Exception {
    String now = getNowPlusMinutes(0);
    String path1 = "/Folder1/path1";
    String path2 = "/Folder2/path2";

    insertFolder(now, "0b01081f80078d29", path1);
    insertFolder(now, "0b01081f80078d30", path2);

    assertTrue(getDocContent(path2, "/Folder1").notFound);
  }

  /* Mock proxy classes backed by the H2 database tables. */
  private class H2BackedTestProxies {
    IDfSessionManager sessionManager = Proxies.newProxyInstance(
        IDfSessionManager.class, new SessionManagerMock());

    public IDfClientX getProxyClientX() {
      return Proxies.newProxyInstance(IDfClientX.class, new ClientXMock());
    }

    private class ClientXMock {
      public IDfQuery getQuery() {
        return Proxies.newProxyInstance(IDfQuery.class, new QueryMock());
      }
    }

    private class QueryMock {
      private String query;

      public void setDQL(String query) {
        this.query = query;
      }

      public IDfCollection execute(IDfSession session, int arg1)
          throws DfException {
        return Proxies.newProxyInstance(IDfCollection.class,
            new CollectionMock(query));
      }
    }

    private class CollectionMock {
      final Statement stmt;
      final ResultSet rs;

      public CollectionMock(String query) throws DfException {
        try {
          stmt = jdbcFixture.getConnection().createStatement();
          query = query.replace("DATETOSTRING", "FORMATDATETIME")
              .replace("DATE(", "PARSEDATETIME(")
              .replace("yyyy-mm-dd hh:mi:ss", "yyyy-MM-dd HH:mm:ss")
              .replace("TYPE(dm_document)", "r_object_type LIKE 'dm_document%'")
              .replace("TYPE(dm_folder)", "r_object_type LIKE 'dm_folder%'")
              .replace("FOLDER(", "(mock_object_path LIKE ")
              .replace("',descend", "%'");
          rs = stmt.executeQuery(query);
        } catch (SQLException e) {
          throw new DfException(e);
        }
      }

      private String[] getRepeatingValue(String colName) throws DfException {
        String value = getString(colName);
        if (Strings.isNullOrEmpty(value)) {
          return new String[0];
        }
        return value.split(",");
      }

      public int getValueCount(String colName) throws DfException {
        return getRepeatingValue(colName).length;
      }

      public String getRepeatingString(String colName, int index)
          throws DfException {
        return getRepeatingValue(colName)[index];
      }

      public String getString(String colName) throws DfException {
        try {
          return rs.getString(colName);
        } catch (SQLException e) {
          throw new DfException(e);
        }
      }

      public boolean next() throws DfException {
        try {
          return rs.next();
        } catch (SQLException e) {
          throw new DfException(e);
        }
      }

      public int getState() {
        return IDfCollection.DF_READY_STATE;
      }

      public void close() throws DfException {
        try {
          rs.close();
          stmt.close();
        } catch (SQLException e) {
          throw new DfException(e);
        }
      }
    }

    private class SessionManagerMock {
      public IDfSession getSession(String docbaseName) {
        return Proxies.newProxyInstance(IDfSession.class, new SessionMock());
      }

      public void release(IDfSession session) {
      }
    }

    private class SessionMock {
      public IDfACL getObject(IDfId id) {
        return Proxies.newProxyInstance(IDfACL.class,
            new AclMock(id.toString()));
      }

      public Object getObjectByQualification(String query) throws DfException {
        if (Strings.isNullOrEmpty(query)) {
          return null;
        }
        try (Statement stmt = jdbcFixture.getConnection().createStatement();
             ResultSet rs = stmt.executeQuery("SELECT * FROM " + query)) {
          if (rs.first()) {
            if (query.toLowerCase().startsWith("dm_user ")) {
              return Proxies.newProxyInstance(IDfUser.class, new UserMock(rs));
            } else if (query.toLowerCase().startsWith("dm_group ")) {
              return
                  Proxies.newProxyInstance(IDfGroup.class, new GroupMock(rs));
            }
          }
          return null;
        } catch (SQLException e) {
          throw new DfException(e);
        }
      }

      public IDfFolder getFolderBySpecification(String spec)
          throws DfException {
        if (Strings.isNullOrEmpty(spec)) {
          return null;
        }
        String query = String.format(
            "SELECT * FROM dm_folder WHERE r_object_id = '%s'", spec);
        try (Statement stmt = jdbcFixture.getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
          if (rs.first()) {
            return
                Proxies.newProxyInstance(IDfFolder.class, new FolderMock(rs));
          }
          return null;
        } catch (SQLException e) {
          throw new DfException(e);
        }
      }

      public IDfType getType(String type) {
        return Proxies.newProxyInstance(IDfType.class, new TypeMock(type));
      }
    }

    private class FolderMock {
      private String[] folderPaths;

      public FolderMock(ResultSet rs) throws SQLException {
        this.folderPaths = rs.getString("r_folder_path").split(",");
      }
       
      public int getFolderPathCount() {
        return folderPaths.length;
      }

      public String getFolderPath(int index) {
        return folderPaths[index];
      }
    }

    private class TypeMock {
      private final String type;

      public TypeMock(String type) {
        this.type = type;
      }

      public boolean isTypeOf(String otherType) {
        return type.startsWith(otherType);
      }
    }

    private class UserMock {
      private String loginName;
      private String source;
      private String ldapDn;
      private boolean isGroup;

      public UserMock(ResultSet rs) throws SQLException {
        loginName = rs.getString("user_login_name");
        source = rs.getString("user_source");
        ldapDn = rs.getString("user_ldap_dn");
        isGroup = rs.getBoolean("r_is_group");
      }

      public String getUserLoginName() {
        return loginName;
      }

      public String getUserSourceAsString() {
        return source;
      }

      public String getUserDistinguishedLDAPName() {
        return ldapDn;
      }

      public boolean isGroup() {
        return isGroup;
      }
    }

    private class GroupMock {
      private String source;

      public GroupMock(ResultSet rs) throws SQLException {
        source = rs.getString("group_source");
      }

      public String getGroupSource() {
        return source;
      }
    }

    private class AccessorInfo {
      String name;
      int permitType;
      int permit;
      boolean isGroup;

      AccessorInfo(String name, int permitType, int permit, boolean isGroup) {
        this.name = name;
        this.permitType = permitType;
        this.permit = permit;
        this.isGroup = isGroup;
      }

      String getName() {
        return name;
      }

      int getPermitType() {
        return permitType;
      }

      int getPermit() {
        return permit;
      }

      boolean isGroup() {
        return isGroup;
      }
    }

    public class AclMock {
      private String id;
      List<AccessorInfo> accessorList = new ArrayList<AccessorInfo>();

      public AclMock(String id) {
        this.id = id;
        try {
          getAccessorInfo();
        } catch (SQLException e) {
          e.printStackTrace();
        }
      }

      private void getAccessorInfo() throws SQLException {
        try (Statement stmt = jdbcFixture.getConnection().createStatement();
            ResultSet rs = stmt.executeQuery(
                "select r_accessor_name, r_accessor_permit, "
                + "r_permit_type, r_is_group from dm_acl "
                + "where r_object_id = '" + id + "'")) {
          while (rs.next()) {
            String accessorName = rs.getString("r_accessor_name");
            int accessorPermit = rs.getInt("r_accessor_permit");
            int accessorPermitType = rs.getInt("r_permit_type");
            boolean isGroup = rs.getBoolean("r_is_group");

            if (!Strings.isNullOrEmpty(accessorName)) {
              accessorList.add(new AccessorInfo(accessorName,
                  accessorPermitType, accessorPermit, isGroup));
            }
          }
        }
      }

      public int getAccessorCount() {
        return accessorList.size();
      }

      public String getAccessorName(int n) {
        return accessorList.get(n).getName();
      }

      public int getAccessorPermitType(int n) {
        return accessorList.get(n).getPermitType();
      }

      public int getAccessorPermit(int n) {
        return accessorList.get(n).getPermit();
      }

      public boolean isGroup(int n) {
        return accessorList.get(n).isGroup();
      }

    }
  }

  private void insertUsers(String... names) throws SQLException {
    for (String name : names) {
      jdbcFixture.executeUpdate(String.format(
          "insert into dm_user(user_name, user_login_name) values('%s', '%s')",
          name, name));
    }
  }

  private void insertGroup(String groupName, String... members)
      throws SQLException {
    insertGroupEx(getNowPlusMinutes(0), "", groupName, members);
  }

  private void insertGroupEx(String lastModified, String source,
      String groupName, String... members) throws SQLException {
    jdbcFixture.executeUpdate(String.format("INSERT INTO dm_user"
        + "(user_name, user_login_name, user_source, user_ldap_dn, r_is_group) "
        + "VALUES('%s', '%s', '%s', '%s', TRUE)", groupName, groupName,
        source, "LDAP".equals(source) ? ("CN=" + groupName) : ""));
    List<String> users = new ArrayList<String>(); 
    List<String> groups = new ArrayList<String>(); 
    for (String member : members) {
      if (member.toLowerCase().startsWith("group")) {
        groups.add(member);
      } else {
        users.add(member);
      }
    }
    Joiner joiner = Joiner.on(',');
    jdbcFixture.executeUpdate(String.format("INSERT INTO dm_group"
        + "(r_object_id, group_name, group_source, users_names, groups_names, "
        + "r_modify_date) VALUES('%s', '%s', '%s', '%s', '%s', {ts '%s'})",
         "12" + groupName, groupName, source, joiner.join(users),
        joiner.join(groups), lastModified));
  }

  private void createAcl(String id) throws SQLException {
    jdbcFixture.executeUpdate(String.format(
        "insert into dm_acl(r_object_id) values('%s')", id));
  }

  private boolean isAccessorGroup(String accessorName) throws SQLException {
    try (Statement stmt = jdbcFixture.getConnection().createStatement();
         ResultSet rs = stmt.executeQuery("select r_is_group from dm_user"
             + " where user_name = '" + accessorName + "'")) {
        if (rs.next()) {
          return rs.getBoolean(1);
        }
      }
    return false;
  }

  private void grantPermit(String id, IDfPermit permit) throws SQLException {
    jdbcFixture.executeUpdate(String.format(
        "insert into dm_acl(r_object_id, r_accessor_name, "
        + "r_accessor_permit, r_permit_type, r_is_group) values("
        + "'%s', '%s', '%s', '%s', '%s')",
        id, permit.getAccessorName(), permit.getPermitValueInt(),
        permit.getPermitType(), isAccessorGroup(permit.getAccessorName())));
  }

  private void addAllowPermitToAcl(String id, String accessorName, int permit)
      throws SQLException {
    IDfPermit permitobj = new DfPermit();
    permitobj.setAccessorName(accessorName);
    permitobj.setPermitType(IDfPermitType.ACCESS_PERMIT);
    permitobj.setPermitValue(Integer.toString(permit));

    grantPermit(id, permitobj);
  }

  private void addDenyPermitToAcl(String id, String accessorName, int permit)
      throws SQLException {
    IDfPermit permitobj = new DfPermit();
    permitobj.setAccessorName(accessorName);
    permitobj.setPermitType(IDfPermitType.ACCESS_RESTRICTION);
    permitobj.setPermitValue(Integer.toString(permit));

    grantPermit(id, permitobj);
  }

  // tests for ACLs
  // TODO: (Srinivas) -  Add a unit test and perform manual test of
  //                     user and group names with quotes in them.
  @Test
  public void testAcls() throws Exception {
    Config config = getTestAdaptorConfig();

    createAcl("4501081f80000100");
    createAcl("4501081f80000101");
    createAcl("4501081f80000102");
    Map<DocId, Acl> namedResources = getAllAcls(config);

    assertEquals(3, namedResources.size());
  }

  @Test
  public void testAllowAcls() throws Exception {
    Config config = getTestAdaptorConfig();

    insertUsers("User1", "User2", "User3", "User4", "User5");
    String id = "4501081f80000100";
    createAcl(id);
    addAllowPermitToAcl(id, "User4", IDfACL.DF_PERMIT_WRITE);
    addAllowPermitToAcl(id, "User5", IDfACL.DF_PERMIT_READ);
    addDenyPermitToAcl(id, "User1", IDfACL.DF_PERMIT_DELETE);
    addDenyPermitToAcl(id, "User2", IDfACL.DF_PERMIT_BROWSE);
    addDenyPermitToAcl(id, "User3", IDfACL.DF_PERMIT_WRITE);

    Map<DocId, Acl> namedResources = getAllAcls(config);
    Acl acl = namedResources.get(new DocId(id));
    assertEquals(ImmutableSet.of(new UserPrincipal("User4", "globalNS"),
        new UserPrincipal("User5", "globalNS")),
        acl.getPermitUsers());
    assertEquals(ImmutableSet.of(new UserPrincipal("User2", "globalNS")),
        acl.getDenyUsers());
    assertEquals(ImmutableSet.of(), acl.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl.getDenyGroups());
  }

  @Test
  public void testBrowseAcls() throws Exception {
    Config config = getTestAdaptorConfig();

    insertUsers("User1", "User2", "User3", "User4", "User5");
    String id = "4501081f80000100";
    createAcl(id);
    addAllowPermitToAcl(id, "User4", IDfACL.DF_PERMIT_WRITE);
    addAllowPermitToAcl(id, "User5", IDfACL.DF_PERMIT_READ);
    addDenyPermitToAcl(id, "User1", IDfACL.DF_PERMIT_DELETE);
    addDenyPermitToAcl(id, "User2", IDfACL.DF_PERMIT_BROWSE);
    addDenyPermitToAcl(id, "User3", IDfACL.DF_PERMIT_WRITE);

    Map<DocId, Acl> namedResources = getAllAcls(config);
    Acl acl = namedResources.get(new DocId(id));
    assertEquals(ImmutableSet.of(new UserPrincipal("User4", "globalNS"),
        new UserPrincipal("User5", "globalNS")),
        acl.getPermitUsers());
    assertEquals(ImmutableSet.of(new UserPrincipal("User2", "globalNS")),
        acl.getDenyUsers());
    assertEquals(ImmutableSet.of(), acl.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl.getDenyGroups());
  }

  @Test
  public void testGroupAcls() throws Exception {
    Config config = getTestAdaptorConfig();

    insertUsers("User1", "User2");
    insertGroup("Group1", "User2", "User3");
    insertGroup("Group2", "User4", "User5");
    insertGroup("Group3", "User6", "User7");
    String id = "4501081f80000101";
    createAcl(id);
    addAllowPermitToAcl(id, "User1", IDfACL.DF_PERMIT_WRITE);
    addAllowPermitToAcl(id, "User2", IDfACL.DF_PERMIT_READ);
    addAllowPermitToAcl(id, "Group1", IDfACL.DF_PERMIT_READ);
    addAllowPermitToAcl(id, "Group2", IDfACL.DF_PERMIT_WRITE);
    addDenyPermitToAcl(id, "Group3", IDfACL.DF_PERMIT_READ);

    Map<DocId, Acl> namedResources = getAllAcls(config);
    Acl acl = namedResources.get(new DocId(id));
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group1", "localNS"),
        new GroupPrincipal("Group2", "localNS")),
        acl.getPermitGroups());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group3", "localNS")),
        acl.getDenyGroups());
    assertEquals(ImmutableSet.of(new UserPrincipal("User1", "globalNS"),
        new UserPrincipal("User2", "globalNS")),
        acl.getPermitUsers());
    assertEquals(ImmutableSet.of(), acl.getDenyUsers());
  }

  @Test
  public void testGroupDmWorldAcl() throws Exception {
    Config config = getTestAdaptorConfig();

    insertUsers("User1", "User3");
    insertGroup("Group1", "User2", "User3");
    insertGroup("dm_world", "User1", "User2", "User3");
    String id = "4501081f80000102";
    createAcl(id);
    addAllowPermitToAcl(id, "Group1", IDfACL.DF_PERMIT_BROWSE);
    addAllowPermitToAcl(id, "dm_world", IDfACL.DF_PERMIT_READ);
    addDenyPermitToAcl(id, "User1", IDfACL.DF_PERMIT_READ);
    addDenyPermitToAcl(id, "User3", IDfACL.DF_PERMIT_WRITE);

    Map<DocId, Acl> namedResources = getAllAcls(config);
    Acl acl = namedResources.get(new DocId(id));
    assertEquals(ImmutableSet.of(new GroupPrincipal("dm_world", "localNS")),
        acl.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl.getDenyGroups());
    assertEquals(ImmutableSet.of(), acl.getPermitUsers());
    assertEquals(ImmutableSet.of(new UserPrincipal("User1", "globalNS")),
        acl.getDenyUsers());
  }

  @Test
  public void testDomainForAclUser() throws Exception {
    Config config = getTestAdaptorConfig();
    config.overrideKey("documentum.windowsDomain", "ajax");

    insertUsers("User1", "User2", "User3", "User4", "User5");
    String id = "4501081f80000100";
    createAcl(id);
    addAllowPermitToAcl(id, "User4", IDfACL.DF_PERMIT_WRITE);
    addAllowPermitToAcl(id, "User5", IDfACL.DF_PERMIT_READ);
    addDenyPermitToAcl(id, "User1", IDfACL.DF_PERMIT_DELETE);
    addDenyPermitToAcl(id, "User2", IDfACL.DF_PERMIT_BROWSE);
    addDenyPermitToAcl(id, "User3", IDfACL.DF_PERMIT_WRITE);

    Map<DocId, Acl> namedResources = getAllAcls(config);

    Acl acl = namedResources.get(new DocId(id));
    assertEquals(ImmutableSet.of(new UserPrincipal("ajax\\User4", "globalNS"),
        new UserPrincipal("ajax\\User5", "globalNS")),
        acl.getPermitUsers());
    assertEquals(ImmutableSet.of(new UserPrincipal("ajax\\User2", "globalNS")),
        acl.getDenyUsers());
  }

  @Test
  public void testDnsDomainForAclUser() throws Exception {
    Config config = getTestAdaptorConfig();
    config.overrideKey("documentum.windowsDomain", "ajax.example.com");

    insertUsers("User1", "User2", "User3", "User4", "User5");
    String id = "4501081f80000100";
    createAcl(id);
    addAllowPermitToAcl(id, "User4", IDfACL.DF_PERMIT_WRITE);
    addAllowPermitToAcl(id, "User5", IDfACL.DF_PERMIT_READ);
    addDenyPermitToAcl(id, "User1", IDfACL.DF_PERMIT_DELETE);
    addDenyPermitToAcl(id, "User2", IDfACL.DF_PERMIT_BROWSE);
    addDenyPermitToAcl(id, "User3", IDfACL.DF_PERMIT_WRITE);

    Map<DocId, Acl> namedResources = getAllAcls(config);
    Acl acl = namedResources.get(new DocId(id));
    assertEquals(ImmutableSet.of(
        new UserPrincipal("ajax.example.com\\User4", "globalNS"),
        new UserPrincipal("ajax.example.com\\User5", "globalNS")),
        acl.getPermitUsers());
    assertEquals(ImmutableSet.of(
        new UserPrincipal("ajax.example.com\\User2", "globalNS")),
        acl.getDenyUsers());
  }

  @Test
  public void testDomainForAclGroup() throws Exception {
    Config config = getTestAdaptorConfig();
    config.overrideKey("documentum.windowsDomain", "ajax");

    insertUsers("User1", "User2");
    insertGroup("Group1", "User2", "User3");
    insertGroup("Group2", "User4", "User5");
    insertGroup("Group3", "User6", "User7");
    String id = "4501081f80000101";
    createAcl(id);
    addAllowPermitToAcl(id, "User1", IDfACL.DF_PERMIT_WRITE);
    addAllowPermitToAcl(id, "User2", IDfACL.DF_PERMIT_READ);
    addAllowPermitToAcl(id, "Group1", IDfACL.DF_PERMIT_READ);
    addAllowPermitToAcl(id, "Group2", IDfACL.DF_PERMIT_WRITE);
    addDenyPermitToAcl(id, "Group3", IDfACL.DF_PERMIT_READ);

    Map<DocId, Acl> namedResources = getAllAcls(config);
    Acl acl = namedResources.get(new DocId(id));
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group1", "localNS"),
        new GroupPrincipal("Group2", "localNS")),
        acl.getPermitGroups());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group3", "localNS")),
        acl.getDenyGroups());
  }

  // Tests for required groups and required group sets.
  private void addRequiredGroupSetToAcl(String id, String accessorName)
      throws SQLException {
    IDfPermit permitobj = new DfPermit();
    permitobj.setAccessorName(accessorName);
    permitobj.setPermitType(IDfPermitType.REQUIRED_GROUP_SET);
    grantPermit(id, permitobj);
  }

  private void addRequiredGroupToAcl(String id, String accessorName)
      throws SQLException {
    IDfPermit permitobj = new DfPermit();
    permitobj.setAccessorName(accessorName);
    permitobj.setPermitType(IDfPermitType.REQUIRED_GROUP);
    grantPermit(id, permitobj);
  }

  @Test
  public void testRequiredGroupSetAcl() throws DfException,
      InterruptedException, SQLException {
    Config config = getTestAdaptorConfig();

    insertUsers("User1", "User2", "User3", "User4", "User5", "User6", "User7");
    insertGroup("Group1", "User2", "User3");
    insertGroup("Group2", "User4", "User5");
    insertGroup("Group3", "User6", "User7");
    insertGroup("GroupSet1", "Group1", "Group2");
    insertGroup("GroupSet2", "Group2", "Group3");
   
    String id = "45Acl0";
    createAcl(id);
    addAllowPermitToAcl(id, "Group1", IDfACL.DF_PERMIT_READ);
    addAllowPermitToAcl(id, "Group2", IDfACL.DF_PERMIT_WRITE);
    addDenyPermitToAcl(id, "Group3", IDfACL.DF_PERMIT_READ);
    addRequiredGroupSetToAcl(id, "GroupSet1");
    addRequiredGroupSetToAcl(id, "GroupSet2");

    Map<DocId, Acl> namedResources = getAllAcls(config);
    assertEquals(2, namedResources.size());

    Acl acl1 = namedResources.get(new DocId("45Acl0_reqGroupSet"));
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl1.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("GroupSet1", "localNS"),
        new GroupPrincipal("GroupSet2", "localNS")),
        acl1.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl1.getDenyGroups());

    Acl acl2 = namedResources.get(new DocId(id));
    assertEquals(new DocId("45Acl0_reqGroupSet"),
        acl2.getInheritFrom());
    assertEquals(InheritanceType.PARENT_OVERRIDES, acl2.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group1", "localNS"),
        new GroupPrincipal("Group2", "localNS")),
        acl2.getPermitGroups());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group3", "localNS")),
        acl2.getDenyGroups());
  }

  @Test
  public void testRequiredGroupsAcl() throws Exception {
    Config config = getTestAdaptorConfig();

    insertUsers("User1", "User2", "User3", "User4", "User5", "User6", "User7");
    insertGroup("Group1", "User2", "User3");
    insertGroup("Group2", "User4", "User5");
    insertGroup("Group3", "User6", "User7");
    insertGroup("Group4", "User2", "User3");
    insertGroup("Group5", "User4", "User5");
    insertGroup("Group6", "User6", "User7");

    String id = "45Acl0";
    createAcl(id);
    addAllowPermitToAcl(id, "Group1", IDfACL.DF_PERMIT_READ);
    addAllowPermitToAcl(id, "Group2", IDfACL.DF_PERMIT_WRITE);
    addDenyPermitToAcl(id, "Group3", IDfACL.DF_PERMIT_READ);
    addRequiredGroupToAcl(id, "Group4");
    addRequiredGroupToAcl(id, "Group5");
    addRequiredGroupToAcl(id, "Group6");

    Map<DocId, Acl> namedResources = getAllAcls(config);
    assertEquals(4, namedResources.size());

    Acl acl1 = namedResources.get(new DocId("45Acl0_Group6"));
    assertEquals(new DocId("45Acl0_Group5"), acl1.getInheritFrom());
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl1.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group6", "localNS")),
        acl1.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl1.getDenyGroups());

    Acl acl2 = namedResources.get(new DocId("45Acl0_Group5"));
    assertEquals(new DocId("45Acl0_Group4"), acl2.getInheritFrom());
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl2.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group5", "localNS")),
        acl2.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl2.getDenyGroups());

    Acl acl3 = namedResources.get(new DocId("45Acl0_Group4"));
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl3.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group4", "localNS")),
        acl3.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl3.getDenyGroups());

    Acl acl4 = namedResources.get(new DocId(id));
    assertEquals(new DocId("45Acl0_Group6"), acl4.getInheritFrom());
    assertEquals(InheritanceType.PARENT_OVERRIDES, acl4.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group1", "localNS"),
        new GroupPrincipal("Group2", "localNS")),
        acl4.getPermitGroups());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group3", "localNS")),
        acl4.getDenyGroups());
  }

  @Test
  public void testRequiredGroupsAndSetsAcl() throws Exception {
    Config config = getTestAdaptorConfig();

    insertUsers("User1", "User2", "User3", "User4", "User5", "User6", "User7");
    insertGroup("Group1", "User2", "User3");
    insertGroup("Group2", "User4", "User5");
    insertGroup("Group3", "User6", "User7");
    insertGroup("Group4", "User2", "User3");
    insertGroup("Group5", "User4", "User5");
    insertGroup("Group6", "User6", "User7");
    insertGroup("GroupSet1", "Group1", "Group2");
    insertGroup("GroupSet2", "Group5", "Group6");

    String id = "45Acl0";
    createAcl(id);
    addAllowPermitToAcl(id, "Group1", IDfACL.DF_PERMIT_READ);
    addAllowPermitToAcl(id, "Group2", IDfACL.DF_PERMIT_WRITE);
    addDenyPermitToAcl(id, "Group3", IDfACL.DF_PERMIT_READ);
    addRequiredGroupToAcl(id, "Group4");
    addRequiredGroupToAcl(id, "Group5");
    addRequiredGroupToAcl(id, "Group6");
    addRequiredGroupSetToAcl(id, "GroupSet1");
    addRequiredGroupSetToAcl(id, "GroupSet2");

    Map<DocId, Acl> namedResources = getAllAcls(config);
    assertEquals(5, namedResources.size());

    Acl acl1 = namedResources.get(new DocId("45Acl0_Group6"));
    assertEquals(new DocId("45Acl0_Group5"), acl1.getInheritFrom());
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl1.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group6", "localNS")),
        acl1.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl1.getDenyGroups());

    Acl acl2 = namedResources.get(new DocId("45Acl0_Group5"));
    assertEquals(new DocId("45Acl0_Group4"), acl2.getInheritFrom());
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl2.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group5", "localNS")),
        acl2.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl2.getDenyGroups());

    Acl acl3 = namedResources.get(new DocId("45Acl0_Group4"));
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl3.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group4", "localNS")),
        acl3.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl3.getDenyGroups());

    Acl acl4 = namedResources.get(new DocId("45Acl0_reqGroupSet"));
    assertEquals(new DocId("45Acl0_Group6"), acl4.getInheritFrom());
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl4.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("GroupSet1", "localNS"),
        new GroupPrincipal("GroupSet2", "localNS")),
        acl4.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl4.getDenyGroups());

    Acl acl5 = namedResources.get(new DocId(id));
    assertEquals(new DocId("45Acl0_reqGroupSet"),
        acl5.getInheritFrom());
    assertEquals(InheritanceType.PARENT_OVERRIDES, acl5.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group1", "localNS"),
        new GroupPrincipal("Group2", "localNS")),
        acl5.getPermitGroups());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group3", "localNS")),
        acl5.getDenyGroups());
  }

  // TODO(srinivas): we should check whether we have a test of non-existent
  // users and groups in permits and denies.
  @Test
  public void testMissingRequiredGroup() throws Exception {
    Config config = getTestAdaptorConfig();

    insertUsers("User1", "User2", "User3");
    insertGroup("Group1", "User2", "User3");

    String id = "45Acl0";
    createAcl(id);
    addAllowPermitToAcl(id, "Group1", IDfACL.DF_PERMIT_READ);
    addRequiredGroupToAcl(id, "GroupNotExists");

    Map<DocId, Acl> namedResources = getAllAcls(config);
    assertEquals(2, namedResources.size());

    // TODO(srinivas): non-existent groups should be dropped from the ACL?
    Acl acl1 = namedResources.get(new DocId("45Acl0_GroupNotExists"));
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl1.getInheritanceType());
    assertEquals(
        ImmutableSet.of(new GroupPrincipal("GroupNotExists", "localNS")),
        acl1.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl1.getDenyGroups());

    Acl acl2 = namedResources.get(new DocId(id));
    assertEquals(new DocId("45Acl0_GroupNotExists"),
        acl2.getInheritFrom());
    assertEquals(InheritanceType.PARENT_OVERRIDES, acl2.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group1", "localNS")),
        acl2.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl2.getDenyGroups());
  }

  /* TODO(bmj): This should create the adaptor, init it with config, then call
   * its getDocIds method with a recording pusher and return the pushed acls.
   */
  private Map<DocId, Acl> getAllAcls(Config config) throws DfException {
    H2BackedTestProxies proxyCls = new H2BackedTestProxies();
    IDfSession session = proxyCls.sessionManager
        .getSession(config.getValue("documentum.docbaseName"));
    try {
      Principals principals = new Principals(session, "localNS",
          config.getValue("adaptor.namespace"),
          config.getValue("documentum.windowsDomain"));
      return new DocumentumAcls(proxyCls.getProxyClientX(), session, principals)
          .getAcls();
    } finally {
      proxyCls.sessionManager.release(session);
    }
  }

  private void insertAclAudit(String id, String chronicleId, String auditObjId,
      String eventName, String date) throws SQLException {
    jdbcFixture.executeUpdate(String.format(
        "insert into dm_audittrail_acl(r_object_id, chronicle_id, "
            + "audited_obj_id, event_name, time_stamp_utc) "
            + "values('%s', '%s', '%s', '%s', {ts '%s'})",
            id, chronicleId, auditObjId, eventName, date));
  }

  private DocumentumAcls getDocumentumAcls() throws DfException {
    H2BackedTestProxies proxyCls = new H2BackedTestProxies();
    DocumentumAdaptor adaptor =
        new DocumentumAdaptor(proxyCls.getProxyClientX());
    Config config = getTestAdaptorConfig();
    IDfSession session = proxyCls.sessionManager.getSession("test");
    DocumentumAcls dctmAcls =
        new DocumentumAcls(proxyCls.getProxyClientX(), session, new Principals(
            session, "localNS", config.getValue("adaptor.namespace"),
            config.getValue("documentum.windowsDomain")));
    return dctmAcls;
  }

  /**
   * Returns date string for the given number of minutes into the future
   * or past.
   *
   * @param minutes minutes to add.
   * @return date in string format.
   */
  private String getNowPlusMinutes(int minutes) {
    Calendar calendar = Calendar.getInstance();
    calendar.add(Calendar.MINUTE, minutes);
    return dateFormat.format(calendar.getTime());
  }

  @Test
  public void testUpdateAcls() throws Exception {
    DocumentumAcls dctmAcls = getDocumentumAcls();

    createAcl("4501081f80000100");
    createAcl("4501081f80000101");
    createAcl("4501081f80000102");
    String dateStr = getNowPlusMinutes(5);
    insertAclAudit("123", "234", "4501081f80000100", "dm_save", dateStr);
    insertAclAudit("124", "235", "4501081f80000101", "dm_saveasnew", dateStr);
    insertAclAudit("125", "236", "4501081f80000102", "dm_destroy", dateStr);

    Map<DocId, Acl> aclMap = dctmAcls.getUpdateAcls(new Checkpoint());
    assertEquals(ImmutableSet.of(
        new DocId("4501081f80000100"),
        new DocId("4501081f80000101"),
        new DocId("4501081f80000102")), aclMap.keySet());
    assertEquals(new Checkpoint(dateStr, "125"),
        dctmAcls.getUpdateAclsCheckpoint());

    Acl acl = aclMap.get(new DocId("4501081f80000100"));
    assertTrue(acl.getPermitUsers().isEmpty());
  }

  @Test
  public void testUpdateAclsWithSameChronicleId() throws Exception {
    DocumentumAcls dctmAcls = getDocumentumAcls();

    createAcl("4501081f80000100");
    createAcl("4501081f80000101");
    createAcl("4501081f80000102");
    String dateStr = getNowPlusMinutes(6);
    insertAclAudit("123", "234", "4501081f80000100", "dm_save", dateStr);
    insertAclAudit("124", "234", "4501081f80000101", "dm_saveasnew", dateStr);
    insertAclAudit("125", "234", "4501081f80000102", "dm_destroy", dateStr);

    Map<DocId, Acl> aclMap = dctmAcls.getUpdateAcls(new Checkpoint());
    assertEquals(ImmutableSet.of(new DocId("4501081f80000100")),
        aclMap.keySet());
    assertEquals(new Checkpoint(dateStr, "125"),
        dctmAcls.getUpdateAclsCheckpoint());
  }

  @Test
  public void testPreviouslyUpdatedAcls() throws Exception {
    DocumentumAcls dctmAcls = getDocumentumAcls();

    createAcl("4501081f80000100");
    createAcl("4501081f80000101");
    createAcl("4501081f80000102");
    String dateStr = getNowPlusMinutes(-10);
    insertAclAudit("123", "234", "4501081f80000100", "dm_save", dateStr);
    insertAclAudit("124", "235", "4501081f80000101", "dm_saveasnew", dateStr);
    insertAclAudit("125", "236", "4501081f80000102", "dm_destroy", dateStr);

    Checkpoint checkpoint = new Checkpoint(getNowPlusMinutes(0), "0");
    Map<DocId, Acl> aclMap = dctmAcls.getUpdateAcls(checkpoint);
    assertEquals(ImmutableMap.of(), aclMap);
    assertEquals(checkpoint, dctmAcls.getUpdateAclsCheckpoint());
  }

  @Test
  public void testMultiUpdateAcls() throws Exception {
    DocumentumAcls dctmAcls = getDocumentumAcls();

    createAcl("4501081f80000100");
    createAcl("4501081f80000101");
    createAcl("4501081f80000102");
    String dateStr = getNowPlusMinutes(10);
    insertAclAudit("123", "234", "4501081f80000100", "dm_save", dateStr);
    insertAclAudit("124", "235", "4501081f80000101", "dm_saveasnew", dateStr);
    insertAclAudit("125", "236", "4501081f80000102", "dm_saveasnew", dateStr);

    Map<DocId, Acl> aclMap = dctmAcls.getUpdateAcls(new Checkpoint());
    assertEquals(ImmutableSet.of(
        new DocId("4501081f80000100"),
        new DocId("4501081f80000101"),
        new DocId("4501081f80000102")), aclMap.keySet());
    assertEquals(new Checkpoint(dateStr, "125"),
        dctmAcls.getUpdateAclsCheckpoint());

    dateStr = getNowPlusMinutes(15);
    insertAclAudit("126", "237", "4501081f80000103", "dm_saveasnew", dateStr);
    insertAclAudit("127", "238", "4501081f80000104", "dm_destroy", dateStr);

    aclMap = dctmAcls.getUpdateAcls(dctmAcls.getUpdateAclsCheckpoint());
    assertEquals(ImmutableSet.of(
        new DocId("4501081f80000103"), 
        new DocId("4501081f80000104")), aclMap.keySet());
    assertEquals(new Checkpoint(dateStr, "127"),
        dctmAcls.getUpdateAclsCheckpoint());
  }

  @Test
  public void testMultiUpdateAclsWithNoResults() throws Exception {
    DocumentumAcls dctmAcls = getDocumentumAcls();

    createAcl("4501081f80000106");
    createAcl("4501081f80000107");
    String dateStr = getNowPlusMinutes(20);
    insertAclAudit("128", "234", "4501081f80000106", "dm_saveasnew", dateStr);
    insertAclAudit("129", "235", "4501081f80000107", "dm_saveasnew", dateStr);

    Map<DocId, Acl> aclMap = dctmAcls.getUpdateAcls(new Checkpoint());
    assertEquals(ImmutableSet.of(
        new DocId("4501081f80000106"),
        new DocId("4501081f80000107")), aclMap.keySet());
    Checkpoint checkpoint = dctmAcls.getUpdateAclsCheckpoint();
    assertEquals(new Checkpoint(dateStr, "129"), checkpoint);

    aclMap = dctmAcls.getUpdateAcls(checkpoint);
    assertEquals(ImmutableSet.of(), aclMap.keySet());
    assertEquals(checkpoint, dctmAcls.getUpdateAclsCheckpoint());
  }

  @Test
  public void testCheckpoint() throws Exception {
    Checkpoint checkpoint = new Checkpoint();
    assertEquals("0", checkpoint.getObjectId());
    assertNotNull(checkpoint.getLastModified());
    assertTrue(checkpoint.equals(checkpoint));

    checkpoint = new Checkpoint("foo", "bar");
    assertEquals("foo", checkpoint.getLastModified());
    assertEquals("bar", checkpoint.getObjectId());
    assertTrue(checkpoint.equals(checkpoint));
    assertTrue(checkpoint.equals(new Checkpoint("foo", "bar")));
    assertFalse(checkpoint.equals(null));
    assertFalse(checkpoint.equals(new Checkpoint()));
    assertFalse(checkpoint.equals(new Checkpoint("foo", "xyzzy")));
  }

  @Test
  public void testGetGroupsDmWorldOnly() throws Exception {
    Config config = getTestAdaptorConfig();
    insertUsers("User1", "User2", "User3", "User4", "User5");

    // The only group should be the virtual group, dm_world, which consists
    // of all users.
    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of(new GroupPrincipal("dm_world", "localNS"),
            ImmutableSet.of(new UserPrincipal("User1", "globalNS"),
                            new UserPrincipal("User2", "globalNS"),
                            new UserPrincipal("User3", "globalNS"),
                            new UserPrincipal("User4", "globalNS"),
                            new UserPrincipal("User5", "globalNS")));

    Map<GroupPrincipal, Collection<Principal>> groups = getGroups(config);

    assertEquals(expected, groups);
  }

  @Test
  public void testGetGroupsUserMembersOnly() throws Exception {
    Config config = getTestAdaptorConfig();
    insertUsers("User1", "User2", "User3", "User4", "User5");
    insertGroup("Group1", "User1", "User2", "User3");
    insertGroup("Group2", "User3", "User4", "User5");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of(new GroupPrincipal("Group1", "localNS"),
            ImmutableSet.of(new UserPrincipal("User1", "globalNS"),
                            new UserPrincipal("User2", "globalNS"),
                            new UserPrincipal("User3", "globalNS")),
            new GroupPrincipal("Group2", "localNS"),
            ImmutableSet.of(new UserPrincipal("User3", "globalNS"),
                            new UserPrincipal("User4", "globalNS"),
                            new UserPrincipal("User5", "globalNS")));

    Map<GroupPrincipal, Collection<Principal>> groups = getGroups(config);

    assertEquals(expected, filterDmWorld(groups));
  }

  @Test
  public void testGetGroupsInvalidMembers() throws Exception {
    Config config = getTestAdaptorConfig();
    insertUsers("User1", "User3", "User5");
    insertGroup("Group1", "User1", "User2", "User3");
    insertGroup("Group2", "User3", "User4", "User5");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of(new GroupPrincipal("Group1", "localNS"),
            ImmutableSet.of(new UserPrincipal("User1", "globalNS"),
                            new UserPrincipal("User3", "globalNS")),
            new GroupPrincipal("Group2", "localNS"),
            ImmutableSet.of(new UserPrincipal("User3", "globalNS"),
                            new UserPrincipal("User5", "globalNS")));

    Map<GroupPrincipal, Collection<Principal>> groups = getGroups(config);

    assertEquals(expected, filterDmWorld(groups));
  }

  @Test
  public void testGetGroupsEmptyGroup() throws Exception {
    Config config = getTestAdaptorConfig();
    insertUsers("User1", "User3", "User5");
    insertGroup("Group1", "User1", "User2", "User3");
    insertGroup("Group2");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of(new GroupPrincipal("Group1", "localNS"),
            ImmutableSet.of(new UserPrincipal("User1", "globalNS"),
                            new UserPrincipal("User3", "globalNS")),
            new GroupPrincipal("Group2", "localNS"),
            ImmutableSet.<Principal>of());

    Map<GroupPrincipal, Collection<Principal>> groups = getGroups(config);

    assertEquals(expected, filterDmWorld(groups));
  }

  @Test
  public void testGetGroupsUserAndGroupMembers() throws Exception {
    Config config = getTestAdaptorConfig();
    insertUsers("User1", "User2", "User3", "User4", "User5");
    insertGroup("Group1", "User1", "User2", "User3");
    insertGroup("Group2", "Group1", "User4", "User5");

   ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
       expected = ImmutableMap.of(new GroupPrincipal("Group1", "localNS"),
           ImmutableSet.of(new UserPrincipal("User1", "globalNS"),
                           new UserPrincipal("User2", "globalNS"),
                           new UserPrincipal("User3", "globalNS")),
           new GroupPrincipal("Group2", "localNS"),
           ImmutableSet.of(new GroupPrincipal("Group1", "localNS"),
                           new UserPrincipal("User4", "globalNS"),
                           new UserPrincipal("User5", "globalNS")));

    Map<GroupPrincipal, Collection<Principal>> groups = getGroups(config);

    assertEquals(expected, filterDmWorld(groups));
  }

  @Test
  public void testGetGroupsDifferentMemberLoginName() throws Exception {
    Config config = getTestAdaptorConfig();
    insertUsers("User1", "User2");
    jdbcFixture.executeUpdate("insert into dm_user(user_name, user_login_name) "
        + "values('User3', 'UserTres')");
    insertGroup("Group1", "User1", "User2", "User3");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of(new GroupPrincipal("Group1", "localNS"),
            ImmutableSet.of(new UserPrincipal("User1", "globalNS"),
                            new UserPrincipal("User2", "globalNS"),
                            new UserPrincipal("UserTres", "globalNS")));

    Map<GroupPrincipal, Collection<Principal>> groups = getGroups(config);

    assertEquals(expected, filterDmWorld(groups));
  }

  @Test
  public void testGetGroupsDifferentGroupLoginName() throws Exception {
    Config config = getTestAdaptorConfig();
    insertUsers("User1", "User2");
    jdbcFixture.executeUpdate(
        "insert into dm_user(user_name, user_login_name, r_is_group) "
        + "values('Group1', 'GroupUno', TRUE)");
    jdbcFixture.executeUpdate(
        "insert into dm_group(group_name, users_names, groups_names) "
        + "values('Group1', 'User1,User2', '')");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of(new GroupPrincipal("GroupUno", "localNS"),
            ImmutableSet.of(new UserPrincipal("User1", "globalNS"),
                            new UserPrincipal("User2", "globalNS")));

    Map<GroupPrincipal, Collection<Principal>> groups = getGroups(config);

    assertEquals(expected, filterDmWorld(groups));
  }

  @Test
  public void testGetGroupsMemberLdapDn() throws Exception {
    Config config = getTestAdaptorConfig();
    insertUsers("User1", "User2");
    jdbcFixture.executeUpdate("insert into dm_user(user_name, user_login_name, "
        + "user_source, user_ldap_dn, r_is_group) values('User3', 'User3', "
        + "'LDAP', 'cn=User3,dc=test,dc=com', TRUE)");
    insertGroup("Group1", "User1", "User2", "User3");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of(new GroupPrincipal("Group1", "localNS"),
            ImmutableSet.of(new UserPrincipal("User1", "globalNS"),
                            new UserPrincipal("User2", "globalNS"),
                            new UserPrincipal("test\\User3", "globalNS")));

    Map<GroupPrincipal, Collection<Principal>> groups = getGroups(config);

    assertEquals(expected, filterDmWorld(groups));
  }

  @Test
  public void testGetGroupsGroupLdapDn() throws Exception {
    Config config = getTestAdaptorConfig();
    insertUsers("User1", "User2");
    jdbcFixture.executeUpdate("insert into dm_user(user_name, user_login_name, "
        + "user_source, user_ldap_dn) values('Group1', 'Group1', 'LDAP', "
        + "'cn=Group1,dc=test,dc=com')");
    jdbcFixture.executeUpdate("insert into dm_group(group_name, group_source, "
        + "users_names, groups_names) values('Group1', 'LDAP', 'User1,User2', "
        + "'')");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected =
            ImmutableMap.of(new GroupPrincipal("test\\Group1", "globalNS"),
                ImmutableSet.of(new UserPrincipal("User1", "globalNS"),
                                new UserPrincipal("User2", "globalNS")));

    Map<GroupPrincipal, Collection<Principal>> groups = getGroups(config);

    assertEquals(expected, filterDmWorld(groups));
  }

  @Test
  public void testGetGroupsWindowsDomainUsers() throws Exception {
    Config config = getTestAdaptorConfig();
    config.overrideKey("documentum.windowsDomain", "TEST");
    insertUsers("User1", "User2", "User3", "User4", "User5");
    insertGroup("Group1", "User1", "User2", "User3");
    insertGroup("Group2", "Group1", "User4", "User5");

   ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
       expected = ImmutableMap.of(new GroupPrincipal("Group1", "localNS"),
           ImmutableSet.of(new UserPrincipal("TEST\\User1", "globalNS"),
                           new UserPrincipal("TEST\\User2", "globalNS"),
                           new UserPrincipal("TEST\\User3", "globalNS")),
           new GroupPrincipal("Group2", "localNS"),
           ImmutableSet.of(new GroupPrincipal("Group1", "localNS"),
                           new UserPrincipal("TEST\\User4", "globalNS"),
                           new UserPrincipal("TEST\\User5", "globalNS")));

    Map<GroupPrincipal, Collection<Principal>> groups = getGroups(config);

    assertEquals(expected, filterDmWorld(groups));
  }

  @Test
  public void testGetGroupsLocalAndGlobalGroups() throws Exception {
    Config config = getTestAdaptorConfig();
    insertUsers("User1", "User2", "User3", "User4", "User5");
    insertGroup("Group1", "User1", "User2", "User3");
    insertLdapGroup("Group2", "User3", "User4", "User5");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of(new GroupPrincipal("Group1", "localNS"),
            ImmutableSet.of(new UserPrincipal("User1", "globalNS"),
                            new UserPrincipal("User2", "globalNS"),
                            new UserPrincipal("User3", "globalNS")),
            new GroupPrincipal("Group2", "globalNS"),
            ImmutableSet.of(new UserPrincipal("User3", "globalNS"),
                            new UserPrincipal("User4", "globalNS"),
                            new UserPrincipal("User5", "globalNS")));

    Map<GroupPrincipal, Collection<Principal>> groups = getGroups(config);

    assertEquals(expected, filterDmWorld(groups));
  }

  @Test
  public void testGetGroupsGlobalGroupMembers() throws Exception {
    Config config = getTestAdaptorConfig();
    insertUsers("User1", "User2", "User3", "User4", "User5");
    insertLdapGroup("Group1", "User1", "User2", "User3");
    insertGroup("Group2", "Group1", "User4", "User5");

   ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
       expected = ImmutableMap.of(new GroupPrincipal("Group1", "globalNS"),
           ImmutableSet.of(new UserPrincipal("User1", "globalNS"),
                           new UserPrincipal("User2", "globalNS"),
                           new UserPrincipal("User3", "globalNS")),
           new GroupPrincipal("Group2", "localNS"),
           ImmutableSet.of(new GroupPrincipal("Group1", "globalNS"),
                           new UserPrincipal("User4", "globalNS"),
                           new UserPrincipal("User5", "globalNS")));

    Map<GroupPrincipal, Collection<Principal>> groups = getGroups(config);

    assertEquals(expected, filterDmWorld(groups));
  }

  @Test
  public void testGetGroupsLocalGroupsOnly() throws Exception {
    Config config = getTestAdaptorConfig();
    config.overrideKey("documentum.pushLocalGroupsOnly", "true");
    insertUsers("User1", "User2", "User3", "User4", "User5");
    insertLdapGroup("Group1", "User1", "User2", "User3");
    insertGroup("Group2", "Group1", "User4", "User5");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
       expected = ImmutableMap.of(new GroupPrincipal("Group2", "localNS"),
           ImmutableSet.of(new GroupPrincipal("Group1", "globalNS"),
                           new UserPrincipal("User4", "globalNS"),
                           new UserPrincipal("User5", "globalNS")));

    Map<GroupPrincipal, Collection<Principal>> groups = getGroups(config);

    assertEquals(expected, filterDmWorld(groups));
  }

  /* Filters the 'dm_world' group out of the map of groups. */
  private <T> Map<GroupPrincipal, T> filterDmWorld(Map<GroupPrincipal, T> map) {
    return Maps.filterKeys(map, new Predicate<GroupPrincipal>() {
        public boolean apply(GroupPrincipal principal) {
          return !"dm_world".equals(principal.getName());
        }
      });
  }

  private void insertLdapGroup(String groupName, String... members)
      throws SQLException {
    insertGroupEx(getNowPlusMinutes(0), "LDAP", groupName, members);
  }

  /* TODO(bmj): This should create the adaptor, init it with config, then call
   * its getDocIds method with a recording pusher and return the pushed groups.
   */
  private Map<GroupPrincipal, Collection<Principal>> getGroups(Config config)
       throws DfException {
    H2BackedTestProxies proxyCls = new H2BackedTestProxies();
    IDfClientX dmClientX = proxyCls.getProxyClientX();
    DocumentumAdaptor adaptor = new DocumentumAdaptor(dmClientX);
    IDfSession session = proxyCls.sessionManager
        .getSession(config.getValue("documentum.docbaseName"));
    try {
      Principals principals = new Principals(session, "localNS",
          config.getValue("adaptor.namespace"),
          config.getValue("documentum.windowsDomain"));
      boolean localGroupsOnly = Boolean.parseBoolean(
          config.getValue("documentum.pushLocalGroupsOnly"));
      return adaptor.getGroups(dmClientX, session, principals, localGroupsOnly);
    } finally {
      proxyCls.sessionManager.release(session);
    }
  }

  @Test
  public void testGetGroupUpdatesNoDmWorld() throws Exception {
    Config config = getTestAdaptorConfig();
    insertUsers("User1", "User2", "User3", "User4", "User5");

    // The virtual group, dm_world, should not be pushed for updates.
    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
      expected = ImmutableMap.<GroupPrincipal, Collection<Principal>>of();

    Checkpoint checkpoint = new Checkpoint();
    checkModifiedGroupsPushed(config, checkpoint, expected, checkpoint);
  }

  @Test
  public void testGetGroupUpdatesAllNew() throws Exception {
    Config config = getTestAdaptorConfig();
    insertUsers("User1", "User2");
    insertModifiedGroup(FEB_1970, "Group1", "User1");
    insertModifiedGroup(MAR_1970, "Group2", "User2");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of(new GroupPrincipal("Group1", "localNS"),
            ImmutableSet.of(new UserPrincipal("User1", "globalNS")),
            new GroupPrincipal("Group2", "localNS"),
            ImmutableSet.of(new UserPrincipal("User2", "globalNS")));

    checkModifiedGroupsPushed(config, new Checkpoint(JAN_1970, "0"),
        expected, new Checkpoint(MAR_1970, "12Group2"));
  }

  @Test
  public void testGetGroupUpdatesSomeNew() throws Exception {
    Config config = getTestAdaptorConfig();
    insertUsers("User1", "User2");
    insertModifiedGroup(JAN_1970, "Group1", "User1");
    insertModifiedGroup(FEB_1970, "Group2", "User2");
    insertModifiedGroup(MAR_1970, "Group3", "User2");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of(new GroupPrincipal("Group2", "localNS"),
            ImmutableSet.of(new UserPrincipal("User2", "globalNS")),
            new GroupPrincipal("Group3", "localNS"),
            ImmutableSet.of(new UserPrincipal("User2", "globalNS")));

    checkModifiedGroupsPushed(config, new Checkpoint(JAN_1970, "12Group1"),
        expected, new Checkpoint(MAR_1970, "12Group3"));
  }

  @Test
  public void testGetGroupUpdatesNoneNew() throws Exception {
    Config config = getTestAdaptorConfig();
    insertUsers("User1", "User2");
    insertModifiedGroup(FEB_1970, "Group1", "User1");
    insertModifiedGroup(MAR_1970, "Group2", "User2");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
      expected = ImmutableMap.<GroupPrincipal, Collection<Principal>>of();

    Checkpoint checkpoint = new Checkpoint(MAR_1970, "12Group2");
    checkModifiedGroupsPushed(config, checkpoint, expected, checkpoint);
  }

  @Test
  public void testGetGroupUpdatesSomeLdapGroups() throws Exception {
    Config config = getTestAdaptorConfig();
    insertUsers("User1", "User2");
    insertModifiedGroup(JAN_1970, "Group1", "User1");
    insertModifiedGroup(FEB_1970, "Group2", "User2");
    insertGroupEx(MAR_1970, "LDAP", "GroupLDAP", "User2");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of(new GroupPrincipal("Group2", "localNS"),
            ImmutableSet.of(new UserPrincipal("User2", "globalNS")),
            new GroupPrincipal("GroupLDAP", "globalNS"),
            ImmutableSet.of(new UserPrincipal("User2", "globalNS")));

    checkModifiedGroupsPushed(config, new Checkpoint(JAN_1970, "12Group1"),
        expected, new Checkpoint(MAR_1970, "12GroupLDAP"));
  }

  @Test
  public void testGetGroupUpdatesLocalGroupsOnly() throws Exception {
    Config config = getTestAdaptorConfig();
    config.overrideKey("documentum.pushLocalGroupsOnly", "true");
    insertUsers("User1", "User2");
    insertModifiedGroup(JAN_1970, "Group1", "User1");
    insertModifiedGroup(FEB_1970, "Group2", "User2");
    insertGroupEx(MAR_1970, "LDAP", "GroupLDAP", "User2");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of(new GroupPrincipal("Group2", "localNS"),
            ImmutableSet.of(new UserPrincipal("User2", "globalNS")));

    checkModifiedGroupsPushed(config, new Checkpoint(JAN_1970, "12Group1"),
        expected, new Checkpoint(FEB_1970, "12Group2"));
  }

  private void insertModifiedGroup(String lastModified, String groupName,
      String... members) throws SQLException {
    insertGroupEx(lastModified, "", groupName, members);
  }

  /* TODO(bmj): This should create the adaptor, init it with config, then call
   * its getModifiedDocIds method with a recording pusher.
   */
  private void checkModifiedGroupsPushed(Config config, Checkpoint checkpoint,
      Map<GroupPrincipal, ? extends Collection<? extends Principal>>
      expectedGroups, Checkpoint expectedCheckpoint)
      throws DfException, IOException, InterruptedException {
    H2BackedTestProxies proxyCls = new H2BackedTestProxies();
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    IDfClientX dmClientX = proxyCls.getProxyClientX();
    DocumentumAdaptor adaptor = new DocumentumAdaptor(dmClientX);
    IDfSession session = proxyCls.sessionManager
        .getSession(config.getValue("documentum.docbaseName"));
    Checkpoint endCheckpoint;
    try {
      Principals principals = new Principals(session, "localNS",
          config.getValue("adaptor.namespace"),
          config.getValue("documentum.windowsDomain"));
      boolean localGroupsOnly = Boolean.parseBoolean(
          config.getValue("documentum.pushLocalGroupsOnly"));
      endCheckpoint = adaptor.pushGroupUpdates(pusher, dmClientX, session,
          principals, localGroupsOnly, checkpoint);
    } finally {
      proxyCls.sessionManager.release(session);
    }
    assertEquals(expectedGroups, pusher.getGroups());
    assertEquals(expectedCheckpoint, endCheckpoint);
  }

  private void insertSysObject(String lastModified, String id, String name,
      String path, String type, String... folderIds) throws SQLException {
    jdbcFixture.executeUpdate(String.format(
        "insert into dm_sysobject(r_object_id, object_name, mock_object_path, "
        + "r_object_type, i_folder_id, r_modify_date) "
        + "values('%s', '%s', '%s', '%s', '%s', {ts '%s'})",
        id, name, path, type, Joiner.on(",").join(folderIds), lastModified));
  }

  private void insertDocument(String lastModified, String id, String path,
      String... folderIds) throws SQLException {
    String name = path.substring(path.lastIndexOf("/") + 1);
    insertSysObject(lastModified, id, name, path, "dm_document", folderIds);
  }

  private void insertFolder(String lastModified, String id, String... paths)
       throws SQLException {
    jdbcFixture.executeUpdate(String.format(
        "insert into dm_folder(r_object_id, r_folder_path) values('%s', '%s')",
        id, Joiner.on(",").join(paths)));
    for (String path : paths) {
      String name = path.substring(path.lastIndexOf("/") + 1);
      insertSysObject(lastModified, id, name, path, "dm_folder");
    }
  }

  /**
   * Builds a list of expected DocId Records that the Pusher should receive.
   *
   * @param folderPath the full path to a folder.
   * @param objectNames ojects within that folder that should be added to the
   *        expected list. If one of the full folderPath is included in
   *        object names, the folder itself is included in the expected results.
   */
  private List<Record> makeExpectedDocIds(String folderPath, 
      String... objectNames) {
    ImmutableList.Builder<Record> builder = ImmutableList.builder();
    for (String name : objectNames) {
      if (name.equals(folderPath)) {
        name = null;
      }
      DocId docid = DocumentumAdaptor.docIdFromPath(folderPath, name);
      builder.add(
          new Record.Builder(docid).setCrawlImmediately(true).build());
    }
    return builder.build();
  }

  /** Convenience method to assemble a list of start paths for readability. */
  private List<String> startPaths(String... paths) {
    return ImmutableList.copyOf(paths);
  }

  @Test
  public void testNoDocuments() throws Exception {
    String folder = "/Folder1";
    Checkpoint startCheckpoint = new Checkpoint();
    checkModifiedDocIdsPushed(startPaths(folder), startCheckpoint,
        ImmutableList.<Record>of(), startCheckpoint);
  }

  @Test
  public void testNoModifiedDocuments() throws Exception {
    String folderId = "0b01081f80001000";
    String folder = "/Folder1";
    insertFolder(JAN_1970, folderId, folder);
    insertDocument(JAN_1970, "0b01081f80001001", folder + "/foo", folderId);
    insertDocument(JAN_1970, "0b01081f80001002", folder + "/bar", folderId);

    Checkpoint startCheckpoint = new Checkpoint();
    checkModifiedDocIdsPushed(startPaths(folder), startCheckpoint,
        ImmutableList.<Record>of(), startCheckpoint);
  }

  @Test
  public void testModifiedDocumentsNoCheckpointObjId() throws Exception {
    String folderId = "0b01081f80001000";
    String folder = "/Folder1";
    insertFolder(JAN_1970, folderId, folder);
    insertDocument(FEB_1970, "0b01081f80001001", folder + "/foo", folderId);
    insertDocument(FEB_1970, "0b01081f80001002", folder + "/bar", folderId);

    checkModifiedDocIdsPushed(startPaths(folder),
        new Checkpoint(EPOCH_1970, "0"),
        makeExpectedDocIds(folder, folder, "foo", "bar"),
        new Checkpoint(FEB_1970, "0b01081f80001002"));
  }

  @Test
  public void testModifiedDocumentsSameCheckpointTime() throws Exception {
    String folderId = "0b01081f80001000";
    String folder = "/Folder1";
    insertFolder(JAN_1970, folderId, folder);
    insertDocument(JAN_1970, "0b01081f80001001", folder + "/foo", folderId);
    insertDocument(JAN_1970, "0b01081f80001002", folder + "/bar", folderId);
    insertDocument(FEB_1970, "0b01081f80001003", folder + "/baz", folderId);

    checkModifiedDocIdsPushed(startPaths(folder),
        new Checkpoint(JAN_1970, "0b01081f80001001"),
        makeExpectedDocIds(folder, "bar", "baz"),
        new Checkpoint(FEB_1970, "0b01081f80001003"));
  }

  @Test
  public void testModifiedDocumentsNewerModifyDate() throws Exception {
    String folderId = "0b01081f80001000";
    String folder = "/Folder1";
    insertFolder(JAN_1970, folderId, folder);
    insertDocument(JAN_1970, "0b01081f80001001", folder + "/foo", folderId);
    insertDocument(FEB_1970, "0b01081f80001002", folder + "/bar", folderId);
    insertDocument(MAR_1970, "0b01081f80001003", folder + "/baz", folderId);

    checkModifiedDocIdsPushed(startPaths(folder),
        new Checkpoint(JAN_1970, "0b01081f80001001"),
        makeExpectedDocIds(folder, "bar", "baz"),
        new Checkpoint(MAR_1970, "0b01081f80001003"));
  }

  @Test
  public void testModifiedFolder() throws Exception {
    String folderId = "0b01081f80001000";
    String folder = "/Folder1";
    insertFolder(JAN_1970, folderId, folder);

    checkModifiedDocIdsPushed(startPaths(folder),
        new Checkpoint(EPOCH_1970, "0b01081f80001003"),
        makeExpectedDocIds(folder, folder),
        new Checkpoint(JAN_1970, folderId));
  }

  @Test
  public void testModifiedFolderNewerThanChildren() throws Exception {
    String folderId = "0b01081f80001000";
    String folder = "/Folder1";
    insertFolder(MAR_1970, folderId, folder);
    insertDocument(JAN_1970, "0b01081f80001001", folder + "/foo", folderId);
    insertDocument(FEB_1970, "0b01081f80001002", folder + "/bar", folderId);
    insertDocument(MAR_1970, "0b01081f80001003", folder + "/baz", folderId);

    checkModifiedDocIdsPushed(startPaths(folder),
        new Checkpoint(JAN_1970, "0b01081f80001001"),
        makeExpectedDocIds(folder, "bar", folder, "baz"),
        new Checkpoint(MAR_1970, "0b01081f80001003"));
  }

  @Test
  public void testModifiedDocumentsOutsideStartPath() throws Exception {
    String folder1Id = "0b01081f80001000";
    String folder1 = "/Folder1";
    insertFolder(JAN_1970, folder1Id, folder1);
    insertDocument(FEB_1970, "0b01081f80001001", folder1 + "/foo", folder1Id);
    insertDocument(FEB_1970, "0b01081f80001002", folder1 + "/bar", folder1Id);
    String folder2Id = "0b01081f80002000";
    String folder2 = "/Folder2";
    insertFolder(JAN_1970, folder2Id, folder2);
    insertDocument(FEB_1970, "0b01081f80002001", folder2 + "/baz", folder2Id);

    checkModifiedDocIdsPushed(startPaths(folder1),
        new Checkpoint(JAN_1970, folder1Id),
        makeExpectedDocIds(folder1, "foo", "bar"),
        new Checkpoint(FEB_1970, "0b01081f80001002"));
  }

  @Test
  public void testModifiedDocumentsOneParentOutsideStartPath()
      throws Exception {
    String folder1Id = "0b01081f80001000";
    String folder1 = "/Folder1";
    insertFolder(JAN_1970, folder1Id, folder1);
    String folder2Id = "0b01081f80002000";
    String folder2 = "/Folder2";
    insertFolder(JAN_1970, folder2Id, folder2);
    insertDocument(FEB_1970, "0b01081f80001001", folder1 + "/foo", folder1Id);
    insertDocument(FEB_1970, "0b01081f80001002", folder1 + "/bar", folder1Id,
                   folder2Id);

    checkModifiedDocIdsPushed(startPaths(folder1),
        new Checkpoint(JAN_1970, folder1Id),
        makeExpectedDocIds(folder1, "foo", "bar"),
        new Checkpoint(FEB_1970, "0b01081f80001002"));
  }

  @Test
  public void testModifiedDocumentsMultipleParentsInStartPaths()
      throws Exception {
    String folder1Id = "0b01081f80001000";
    String folder1 = "/Folder1";
    insertFolder(JAN_1970, folder1Id, folder1);
    String folder2Id = "0b01081f80002000";
    String folder2 = "/Folder2";
    insertFolder(JAN_1970, folder2Id, folder2);
    insertDocument(FEB_1970, "0b01081f80001001", folder1 + "/foo", folder1Id);
    insertDocument(FEB_1970, "0b01081f80001002", folder1 + "/bar", folder1Id,
                   folder2Id);

    checkModifiedDocIdsPushed(startPaths(folder1, folder2),
        new Checkpoint(FEB_1970, folder1Id),
        new ImmutableList.Builder<Record>()
           .addAll(makeExpectedDocIds(folder1, "foo", "bar"))
           .addAll(makeExpectedDocIds(folder2, "bar"))
           .build(),
        new Checkpoint(FEB_1970, "0b01081f80001002"));
  }

  @Test
  public void testModifiedDocumentsMultipleStartPaths() throws Exception {
    String folder1Id = "0b01081f80001000";
    String folder1 = "/Folder1";
    insertFolder(JAN_1970, folder1Id, folder1);
    insertDocument(MAR_1970, "0b01081f80001001", folder1 + "/foo", folder1Id);
    insertDocument(MAR_1970, "0b01081f80001002", folder1 + "/bar", folder1Id);
    String folder2Id = "0b01081f80002000";
    String folder2 = "/Folder2";
    insertFolder(JAN_1970, folder2Id, folder2);
    insertDocument(MAR_1970, "0b01081f80002001", folder2 + "/baz", folder2Id);

    checkModifiedDocIdsPushed(startPaths(folder1, folder2),
        new Checkpoint(FEB_1970, folder1Id),
        new ImmutableList.Builder<Record>()
           .addAll(makeExpectedDocIds(folder1, "foo", "bar"))
           .addAll(makeExpectedDocIds(folder2, "baz"))
           .build(),
        new Checkpoint(MAR_1970, "0b01081f80002001"));
  }

  @Test
  public void testModifiedDocumentsInSubfolder() throws Exception {
    String folder1Id = "0b01081f80001000";
    String folder1 = "/Folder1";
    insertFolder(JAN_1970, folder1Id, folder1);
    insertDocument(MAR_1970, "0b01081f80001001", folder1 + "/foo", folder1Id);
    insertDocument(MAR_1970, "0b01081f80001002", folder1 + "/bar", folder1Id);
    String folder2Id = "0b01081f80002000";
    String folder2 = "/Folder1/Folder2";
    insertFolder(JAN_1970, folder2Id, folder2);
    insertDocument(MAR_1970, "0b01081f80002001", folder2 + "/baz", folder2Id);

    checkModifiedDocIdsPushed(startPaths(folder1),
        new Checkpoint(FEB_1970, folder1Id),
        new ImmutableList.Builder<Record>()
           .addAll(makeExpectedDocIds(folder1, "foo", "bar"))
           .addAll(makeExpectedDocIds(folder2, "baz"))
           .build(),
        new Checkpoint(MAR_1970, "0b01081f80002001"));
  }

  @Test
  public void testModifiedDocumentsNotDocumentOrFolder() throws Exception {
    String folderId = "0b01081f80001000";
    String folder = "/Folder1";
    insertFolder(JAN_1970, folderId, folder);
    insertDocument(FEB_1970, "0b01081f80001001", folder + "/foo", folderId);
    insertDocument(MAR_1970, "0b01081f80001002", folder + "/bar", folderId);
    insertSysObject(MAR_1970, "0b01081f80001003", "baz", folder + "/baz",
        "dm_other", folderId);

    checkModifiedDocIdsPushed(startPaths(folder),
        new Checkpoint(FEB_1970, folder),
        makeExpectedDocIds(folder, "foo", "bar"),
        new Checkpoint(MAR_1970, "0b01081f80001002"));
  }

  @Test
  public void testModifiedDocumentsWithFolderSubtype() throws Exception {
    String folderId = "0b01081f80001000";
    String folder = "/Folder1";
    jdbcFixture.executeUpdate(String.format(
        "insert into dm_folder(r_object_id, r_folder_path) values('%s', '%s')",
        folderId, folder));
    insertSysObject(FEB_1970, folderId, "Folder1", folder, "dm_folder_subtype",
        folderId);
    insertDocument(FEB_1970, "0b01081f80001001", folder + "/foo", folderId);
    insertDocument(MAR_1970, "0b01081f80001002", folder + "/bar", folderId);

    checkModifiedDocIdsPushed(startPaths(folder),
        new Checkpoint(JAN_1970, folderId),
        makeExpectedDocIds(folder, folder, "foo", "bar"),
        new Checkpoint(MAR_1970, "0b01081f80001002"));
  }

  @Test
  public void testModifiedDocumentsWithDocumentSubtype() throws Exception {
    String folderId = "0b01081f80001000";
    String folder = "/Folder1";
    insertFolder(JAN_1970, folderId, folder);
    insertDocument(FEB_1970, "0b01081f80001001", folder + "/foo", folderId);
    insertDocument(MAR_1970, "0b01081f80001002", folder + "/bar", folderId);
    insertSysObject(MAR_1970, "0b01081f80001003", "baz", folder + "/baz",
        "dm_document_subtype", folderId);

    checkModifiedDocIdsPushed(startPaths(folder),
        new Checkpoint(FEB_1970, folder),
        makeExpectedDocIds(folder, "foo", "bar", "baz"),
        new Checkpoint(MAR_1970, "0b01081f80001003"));
  }

  /* TODO(bmj): This should create the adaptor, init it with config, then call
   * its getModifiedDocIds method with a recording pusher.
   */
  private void checkModifiedDocIdsPushed(List<String> startPaths,
      Checkpoint checkpoint, List<Record> expectedDocIds,
      Checkpoint expectedCheckpoint)
      throws DfException, IOException, InterruptedException {
    H2BackedTestProxies proxyCls = new H2BackedTestProxies();
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    IDfClientX dmClientX = proxyCls.getProxyClientX();
    DocumentumAdaptor adaptor = new DocumentumAdaptor(dmClientX);
    IDfSession session = proxyCls.sessionManager.getSession("foo");
    Checkpoint endCheckpoint;
    try {
      endCheckpoint = adaptor.pushDocumentUpdates(pusher, dmClientX, session,
          startPaths, checkpoint);
    } finally {
      proxyCls.sessionManager.release(session);
    }
    assertEquals(expectedDocIds, pusher.getRecords());
    assertEquals(expectedCheckpoint, endCheckpoint);
  }
}
