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
import com.google.enterprise.adaptor.GroupPrincipal;
import com.google.enterprise.adaptor.Principal;
import com.google.enterprise.adaptor.Request;
import com.google.enterprise.adaptor.Response;
import com.google.enterprise.adaptor.UserPrincipal;

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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
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

  private static final String CREATE_TABLE_GROUP = "create table dm_group "
      + "(r_object_id varchar, group_name varchar, group_source varchar, "
      + "groups_names varchar, users_names varchar)";

  private static final String CREATE_TABLE_USER = "create table dm_user "
      + "(user_name varchar primary key, user_login_name varchar, "
      + "user_source varchar, user_ldap_dn varchar, r_is_group boolean)";

  private static final String CREATE_TABLE_ACL = "create table dm_acl "
      + "(r_object_id varchar, r_accessor_name varchar, "
      + "r_accessor_permit int, r_permit_type int, r_is_group boolean)";

  private static final String CREATE_TABLE_AUDITTRAIL_ACL =
      "create table dm_audittrail_acl "
      + "(r_object_id varchar, chronicle_id varchar, audited_obj_id varchar, "
      + "event_name varchar, time_stamp_utc timestamp)";

  private JdbcFixture jdbcFixture = new JdbcFixture();

  @Before
  public void setUp() throws Exception {
    jdbcFixture.executeUpdate(CREATE_TABLE_GROUP, CREATE_TABLE_USER,
        CREATE_TABLE_ACL, CREATE_TABLE_AUDITTRAIL_ACL);
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
    config.addKey("documentum.src", "/Folder1/path1");
    config.addKey("documentum.separatorRegex", ",");
    config.addKey("documentum.excludedAttributes", "foo, bar");
    config.addKey("adaptor.namespace", "globalNS");
    config.addKey("documentum.windowsDomain", "");
    config.addKey("documentum.pushLocalGroupsOnly", "false");
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
    assertEquals("testpwd", proxyCls.password);
    assertEquals("testdocbase", proxyCls.docbaseName);
    assertEquals(1, proxyCls.docbaseLoginInfoMap.size());
    assertEquals(1, proxyCls.docbaseSessionMap.size());

    List<String> expectedMethodCallSequence = Arrays.asList(
        "getLocalClient", "newSessionManager",
        "getLoginInfo", "setIdentity",
        "getSession", "release",
        "getLocalClient", "newSessionManager",
        "getLoginInfo", "setIdentity",
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
  public void testParseStartPathsMultiSeperator() {
    String path1 = "Folder1/path1";
    String path2 = "Folder2/path2";
    String path3 = "Folder3/path3";
    String startPaths = path1 + ";" + path2 + ":" + path3 + ",";

    List<String> paths = DocumentumAdaptor.parseStartPaths(startPaths, "[:;,]");
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

  private void initializeAdaptor(DocumentumAdaptor adaptor, String src,
      String separatorRegex) throws DfException {
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = context.getConfig();

    adaptor.initConfig(config);

    config.overrideKey("documentum.username", "testuser");
    config.overrideKey("documentum.password", "testpwd");
    config.overrideKey("documentum.docbaseName", "testdocbase");
    config.overrideKey("documentum.src", src);
    if (separatorRegex != null) {
      config.overrideKey("documentum.separatorRegex", separatorRegex);
    }

    adaptor.init(context);
  }

  @Test
  public void testConfigSeparatorRegex() throws DfException {
    DocumentumAdaptor adaptor =
        new DocumentumAdaptor(new InitTestProxies().getProxyClientX());
    String path1 = "/Folder1/path1";
    String path2 = "/Folder2/path2";
    String path3 = "/Folder3/path3";
    String path4 = "/Folder4/path4";
    String startPaths = path1 + ";" + path2 + ":" + path3 + "," + path4;

    initializeAdaptor(adaptor, startPaths, "[;:,]");

    assertEquals(ImmutableList.of(path1, path2, path3, path4),
        adaptor.getStartPaths());
  }

  @Test
  public void testConfigBlankSeparatorRegexValue() throws DfException {
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
  public void testConfigNoSeparatorRegexEntry() throws DfException {
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

  /* Mock proxy classes for testing file content */
  private class DocContentTestProxies {
    Map<String, String> objectPathIdsMap = new HashMap<String, String>() {
      {
        put("/Folder1/path1/object1", "0901081f80079f5c");
      }
    };

    String objContentType;
    String objContent;

    String respContentType;
    ByteArrayOutputStream respContentBaos;

    public void setObjectContentType(String objContentType) {
      this.objContentType = objContentType;
    }

    public void setObjectContent(String objContent) {
      this.objContent = objContent;
    }

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
      public IDfSysObject getObjectByPath(String path) {
        if (objectPathIdsMap.containsKey(path)) {
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
        return Proxies.newProxyInstance(IDfId.class, new IdMock());
      }

      public InputStream getContent() {
        if (objectPathIdsMap.containsKey(objectPath) && (objContent != null)) {
          return new ByteArrayInputStream(objContent.getBytes(UTF_8));
        } else {
          return null;
        }
      }

      public IDfType getType() {
        return Proxies.newProxyInstance(IDfType.class, new TypeMock());
      }

      public String getContentType() {
        return objContentType;
      }

      public boolean isVirtualDocument() {
        return false;
      }

      public Enumeration<IDfAttr> enumAttrs() {
        return new Vector<IDfAttr>().elements();  // No attrs.
      }
    }

    private class TypeMock {
      public boolean isTypeOf(String type) {
        return type.equals("dm_document");
      }

      public String getName() {
        return "dm_document";
      }
    }

    private class IdMock {
    }

    public Request getProxyRequest(DocId docId) {
      return Proxies.newProxyInstance(Request.class, new RequestMock(docId));
    }

    private class RequestMock {
      DocId docId;

      public RequestMock(DocId docId) {
        this.docId = docId;
      }

      public DocId getDocId() {
        return docId;
      }
    }

    public Response getProxyResponse() {
      return Proxies.newProxyInstance(Response.class, new ResponseMock());
    }

    private class ResponseMock {
      public void setContentType(String contentType) {
        DocContentTestProxies.this.respContentType = contentType;
      }

      public OutputStream getOutputStream() {
        respContentBaos = new ByteArrayOutputStream();
        return respContentBaos;
      }
    }
  }

  @Test
  public void testDocContent() throws Exception {
    DocContentTestProxies proxyCls = new DocContentTestProxies();
    DocumentumAdaptor adaptor =
        new DocumentumAdaptor(proxyCls.getProxyClientX());

    String objectContentType = "crtext/html";
    String objectContent = "<html><body>Hello</body></html>";
    proxyCls.setObjectContentType(objectContentType);
    proxyCls.setObjectContent(objectContent);
    String path = "/Folder1/path1/object1";
    Request req = proxyCls.getProxyRequest(adaptor.docIdFromPath(path));
    Response resp = proxyCls.getProxyResponse();
    IDfSessionManager sessionManager = proxyCls.getProxySessionManager();

    adaptor.getDocContentHelper(req, resp, sessionManager,
        ProxyAdaptorContext.getInstance().getDocIdEncoder(),
        ImmutableList.of("/Folder1"), null);

    assertEquals(objectContentType, proxyCls.respContentType);
    assertEquals(objectContent,
        proxyCls.respContentBaos.toString(UTF_8.name()));
  }

  /* Mock proxy classes for testing file metadata */
  private class MetadataTestProxies {
    Multimap<String, String> attributes;
    Multimap<String, String> respMetadata = TreeMultimap.create();

    public void setAttributes(Multimap<String, String> attributes) {
      this.attributes = attributes;
    }

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
      public IDfSysObject getObjectByPath(String path) {
        return Proxies.newProxyInstance(IDfSysObject.class,
            new SysObjectMock());
      }
    }

    private class SysObjectMock {
      public IDfId getObjectId() {
        return Proxies.newProxyInstance(IDfId.class, new IdMock());
      }

      public InputStream getContent() {
        return new ByteArrayInputStream("Hello World".getBytes(UTF_8));
      }

      public IDfType getType() {
        return Proxies.newProxyInstance(IDfType.class, new TypeMock());
      }

      public String getContentType() {
        return "text/plain";
      }

      public boolean isVirtualDocument() {
        return false;
      }

      public Enumeration<IDfAttr> enumAttrs() {
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

    private class TypeMock {
      public boolean isTypeOf(String type) {
        return type.equals("dm_document");
      }

      public String getName() {
        return "dm_document";
      }
    }

    private class IdMock {
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

    public Request getProxyRequest(DocId docId) {
      return Proxies.newProxyInstance(Request.class, new RequestMock(docId));
    }

    private class RequestMock {
      DocId docId;

      public RequestMock(DocId docId) {
        this.docId = docId;
      }

      public DocId getDocId() {
        return docId;
      }
    }

    public Response getProxyResponse() {
      return Proxies.newProxyInstance(Response.class, new ResponseMock());
    }

    private class ResponseMock {
      public void setContentType(String contentType) {
      }

      public OutputStream getOutputStream() {
        return new ByteArrayOutputStream();
      }

      public void addMetadata(String name, String value) {
        respMetadata.put(name, value);
      }
    }
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

  private void testMetadata(TreeMultimap<String, String> attrs,
      TreeMultimap<String, String> expected) throws Exception {
    MetadataTestProxies proxyCls = new MetadataTestProxies();
    DocumentumAdaptor adaptor =
        new DocumentumAdaptor(proxyCls.getProxyClientX());

    proxyCls.setAttributes(Multimaps.unmodifiableMultimap(attrs));
    String path = "/Folder1/path1/object1";
    Request req = proxyCls.getProxyRequest(adaptor.docIdFromPath(path));
    Response resp = proxyCls.getProxyResponse();
    IDfSessionManager sessionManager = proxyCls.getProxySessionManager();

    adaptor.getDocContentHelper(req, resp, sessionManager,
        ProxyAdaptorContext.getInstance().getDocIdEncoder(),
        ImmutableList.of("/Folder1"), ImmutableSet.of("foo", "bar"));

    assertEquals(expected, proxyCls.respMetadata);
  }

  /* Mock proxy classes for testing virtual document content */
  private class VirtualDocContentTestProxies {
    Map<String, String> objectPathIdsMap = new HashMap<String, String>() {
      {
        put("/Folder1/path1/vdoc", "0901081f80079f5c");
      }
    };
    List<IDfSysObject>vdocChildren = new ArrayList<IDfSysObject>();

    String objContentType;
    String objContent;

    String respContentType;
    ByteArrayOutputStream respContentBaos;
    Map<String, URI>respAnchors = new HashMap<String, URI>();

    public void setObjectContentType(String objContentType) {
      this.objContentType = objContentType;
    }

    public void setObjectContent(String objContent) {
      this.objContent = objContent;
    }

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
      public IDfSysObject getObjectByPath(String path) {
        if (objectPathIdsMap.containsKey(path)) {
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
        return Proxies.newProxyInstance(IDfId.class, new IdMock());
      }

      public InputStream getContent() {
        if (objectPathIdsMap.containsKey(objectPath) && (objContent != null)) {
          return new ByteArrayInputStream(objContent.getBytes(UTF_8));
        } else {
          return null;
        }
      }

      public IDfType getType() {
        return Proxies.newProxyInstance(IDfType.class, new TypeMock());
      }

      public String getContentType() {
        return objContentType;
      }

      public Enumeration<IDfAttr> enumAttrs() {
        return new Vector<IDfAttr>().elements();  // No attrs.
      }

      public boolean isVirtualDocument() {
        return true;
      }

      public IDfVirtualDocument asVirtualDocument(String lateBinding,
          boolean followRootAssembly) {
        return Proxies.newProxyInstance(IDfVirtualDocument.class,
            new VirtualDocumentMock());
      }
    }

    private class VirtualDocumentMock {
      public IDfVirtualDocumentNode getRootNode() {
        return Proxies.newProxyInstance(IDfVirtualDocumentNode.class,
            new VdocRootNodeMock());
      }
    }

    private class VdocRootNodeMock {
      public int getChildCount() {
        return vdocChildren.size();
      }

      public IDfVirtualDocumentNode getChild(int index) {
        return Proxies.newProxyInstance(IDfVirtualDocumentNode.class,
            new VdocChildNodeMock(vdocChildren.get(index)));
      }
    }

    private class VdocChildNodeMock {
      private final IDfSysObject childObject;
      public VdocChildNodeMock(IDfSysObject childObject) {
        this.childObject = childObject;
      }

      public IDfSysObject getSelectedObject() {
        return childObject;
      }
    }

    public IDfSysObject getProxyVdocChildObject(String id, String name) {
      return Proxies.newProxyInstance(IDfSysObject.class, 
          new VdocChildObjectMock(id, name));
    }

    private class VdocChildObjectMock {
      private final String id;
      private final String name;

      public VdocChildObjectMock(String id, String name) {
        this.id = id;
        this.name = name;
      }

      public String getString(String colName) {
        if ("r_object_id".equals(colName)) {
          return id;
        } else if ("object_name".equals(colName)) {
          return name;
        } else {
          return null;
        }
      }
    }

    private class TypeMock {
      public boolean isTypeOf(String type) {
        return type.equals("dm_document");
      }

      public String getName() {
        return "dm_document";
      }
    }

    private class IdMock {
    }

    public Request getProxyRequest(DocId docId) {
      return Proxies.newProxyInstance(Request.class, new RequestMock(docId));
    }

    private class RequestMock {
      DocId docId;

      public RequestMock(DocId docId) {
        this.docId = docId;
      }

      public DocId getDocId() {
        return docId;
      }
    }

    public Response getProxyResponse() {
      return Proxies.newProxyInstance(Response.class, new ResponseMock());
    }

    private class ResponseMock {
      public void setContentType(String contentType) {
        VirtualDocContentTestProxies.this.respContentType = contentType;
      }

      public OutputStream getOutputStream() {
        respContentBaos = new ByteArrayOutputStream();
        return respContentBaos;
      }

      public void addAnchor(URI uri, String text) {
        respAnchors.put(text, uri);
      }
    }
  }

  @Test
  public void testVirtualDocContentNoChildren() throws Exception {
    VirtualDocContentTestProxies proxyCls = new VirtualDocContentTestProxies();
    DocumentumAdaptor adaptor =
        new DocumentumAdaptor(proxyCls.getProxyClientX());

    String objectContentType = "crtext/html";
    String objectContent = "<html><body>Hello</body></html>";
    proxyCls.setObjectContentType(objectContentType);
    proxyCls.setObjectContent(objectContent);
    String path = "/Folder1/path1/vdoc";
    Request req = proxyCls.getProxyRequest(adaptor.docIdFromPath(path));
    Response resp = proxyCls.getProxyResponse();
    IDfSessionManager sessionManager = proxyCls.getProxySessionManager();

    adaptor.getDocContentHelper(req, resp, sessionManager,
        ProxyAdaptorContext.getInstance().getDocIdEncoder(),
        ImmutableList.of("/Folder1"), null);

    assertEquals(objectContentType, proxyCls.respContentType);
    assertEquals(objectContent,
        proxyCls.respContentBaos.toString(UTF_8.name()));
    assertTrue(proxyCls.respAnchors.isEmpty());
  }

  @Test
  public void testVirtualDocContentWithChildren() throws Exception {
    VirtualDocContentTestProxies proxyCls = new VirtualDocContentTestProxies();
    DocumentumAdaptor adaptor =
        new DocumentumAdaptor(proxyCls.getProxyClientX());

    String objectContentType = "crtext/html";
    String objectContent = "<html><body>Hello</body></html>";
    proxyCls.setObjectContentType(objectContentType);
    proxyCls.setObjectContent(objectContent);
    String path = "/Folder1/path1/vdoc";
    proxyCls.vdocChildren.add(
        proxyCls.getProxyVdocChildObject("0901081f80079f5d", "object1"));
    proxyCls.vdocChildren.add(
        proxyCls.getProxyVdocChildObject("0901081f80079f5e", "object2"));
    proxyCls.vdocChildren.add(
        proxyCls.getProxyVdocChildObject("0901081f80079f5f", "object3"));

    Request req = proxyCls.getProxyRequest(adaptor.docIdFromPath(path));
    Response resp = proxyCls.getProxyResponse();
    IDfSessionManager sessionManager = proxyCls.getProxySessionManager();

    adaptor.getDocContentHelper(req, resp, sessionManager,
        ProxyAdaptorContext.getInstance().getDocIdEncoder(),
        ImmutableList.of("/Folder1"), null);

    assertEquals(objectContentType, proxyCls.respContentType);
    assertEquals(objectContent,
        proxyCls.respContentBaos.toString(UTF_8.name()));

    // Verify child links.
    assertEquals(proxyCls.vdocChildren.size(), proxyCls.respAnchors.size());
    for (String name : ImmutableList.of("object1", "object2", "object3")) {
      URI uri = proxyCls.respAnchors.get(name);
      assertNotNull(uri);
      assertTrue(uri.toString().endsWith(path + "/" + name));
    }
  }

  /* Mock proxy classes for testing folder listing */
  private class FolderDocContentTestProxies {
    Map<String, String> folderPathIdsMap = new HashMap<String, String>();
    List<String> folderListingIds = new ArrayList<String>();
    List<String> folderListingNames = new ArrayList<String>();

    boolean respNotFound = false;
    String respContentType;
    ByteArrayOutputStream respContentBaos;

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
        return getProxySession();
      }
    }

    public IDfSession getProxySession() {
      return Proxies.newProxyInstance(IDfSession.class, new SessionMock());
    }

    private class SessionMock {
      public IDfFolder getObjectByPath(String path) {
        if (folderPathIdsMap.containsKey(path)) {
          return getProxyFolderObject(path);
        } else {
          return null;
        }
      }
    }

    public IDfFolder getProxyFolderObject(String objectPath) {
      return Proxies.newProxyInstance(IDfFolder.class,
          new FolderMock(objectPath));
    }

    private class FolderMock {
      private String objectPath;

      public FolderMock(String objectPath) {
        this.objectPath = objectPath;
      }

      public IDfId getObjectId() {
        String objId = folderPathIdsMap.get(objectPath);
        return getProxyId(objId);
      }

      public String getObjectName() {
        String[] parts = objectPath.split("/", 0);
        return parts[parts.length - 1];
      }

      public IDfCollection getContents(String colNames) {
        return getProxyCollection(colNames);
      }

      public IDfType getType() {
        return getProxyType();
      }

      public Enumeration<IDfAttr> enumAttrs() {
        return new Vector<IDfAttr>().elements();  // No attrs.
      }
    }

    public IDfCollection getProxyCollection(String colNames) {
      return Proxies
          .newProxyInstance(IDfCollection.class, new CollectionMock(colNames));
    }

    private class CollectionMock {
      private String colNames;
      Iterator<String> iterIds;
      Iterator<String> iterNames;

      public  CollectionMock(String colNames) {
        this.colNames = colNames;
        iterIds = folderListingIds.iterator();
        iterNames =  folderListingNames.iterator();
      }

      public String getString(String colName) {
        if ("r_object_id".equals(colName)) {
          return iterIds.next();
        } else if ("object_name".equals(colName)) {
          return iterNames.next();
        } else {
          return null;
        }
      }

      public boolean next() {
        return iterIds.hasNext() && iterNames.hasNext();
      }

      public void close() {
      }
    }

    public IDfType getProxyType() {
      return Proxies.newProxyInstance(IDfType.class, new TypeMock());
    }

    private class TypeMock {
      public boolean isTypeOf(String type) {
        return type.equals("dm_folder");
      }

      public String getName() {
        return "dm_folder";
      }
    }

    public IDfId getProxyId(String id) {
      return Proxies.newProxyInstance(IDfId.class, new IdMock(id));
    }

    private class IdMock {
      public IdMock(String objectId) {
      }
    }

    public Request getProxyRequest(DocId docId) {
      return Proxies.newProxyInstance(Request.class, new RequestMock(docId));
    }

    private class RequestMock {
      DocId docId;

      public RequestMock(DocId docId) {
        this.docId = docId;
      }

      public DocId getDocId() {
        return docId;
      }
    }

    public Response getProxyResponse() {
      return Proxies.newProxyInstance(Response.class, new ResponseMock());
    }

    private class ResponseMock {
      public void respondNotFound() {
        respNotFound = true;
      }

      public void setContentType(String contentType) {
        FolderDocContentTestProxies.this.respContentType = contentType;
      }

      public OutputStream getOutputStream() {
        respContentBaos = new ByteArrayOutputStream();
        return respContentBaos;
      }
    }
  }

  private void addFolder(FolderDocContentTestProxies proxyCls, String id,
      String path) {
    proxyCls.folderPathIdsMap.put(path, id);
  }

  private void addFolderChild(FolderDocContentTestProxies proxyCls, String id,
      String name) {
    proxyCls.folderListingIds.add(id);
    proxyCls.folderListingNames.add(name);
  }

  @Test
  public void testFolderDocContent() throws Exception {
    FolderDocContentTestProxies proxyCls = new FolderDocContentTestProxies();
    DocumentumAdaptor adaptor =
        new DocumentumAdaptor(proxyCls.getProxyClientX());

    String folder = "/Folder2/subfolder/path2";

    Request req = proxyCls.getProxyRequest(adaptor.docIdFromPath(folder));
    Response resp = proxyCls.getProxyResponse();
    IDfSessionManager sessionManager = proxyCls.getProxySessionManager();

    addFolder(proxyCls, "0b01081f80078d29", folder);
    StringBuilder expected = new StringBuilder();
    expected.append("<!DOCTYPE html>\n<html><head><title>");
    expected.append("Folder path2");
    expected.append("</title></head><body><h1>");
    expected.append("Folder path2");
    expected.append("</h1>");

    addFolderChild(proxyCls, "0901081f80079263", "file1");
    expected.append("<li><a href=\"path2/file1\">file1</a></li>");

    addFolderChild(proxyCls, "0901081f8007926d", "file2 evil<chars?");
    expected.append("<li><a href=\"path2/file2%20evil%3Cchars%3F\">"
        + "file2 evil&lt;chars?</a></li>");

    addFolderChild(proxyCls, "0901081f80079278", "file3");
    expected.append("<li><a href=\"path2/file3\">file3</a></li>");

    expected.append("</body></html>");

    adaptor.getDocContentHelper(req, resp, sessionManager, 
        ProxyAdaptorContext.getInstance().getDocIdEncoder(),
        ImmutableList.of("/Folder2"), null);

    assertFalse(proxyCls.respNotFound);
    assertEquals("text/html; charset=UTF-8", proxyCls.respContentType);
    assertEquals(expected.toString(),
        proxyCls.respContentBaos.toString(UTF_8.name()));
  }

  @Test
  public void testGetDocContentNotFound() throws Exception {
    FolderDocContentTestProxies proxyCls = new FolderDocContentTestProxies();
    DocumentumAdaptor adaptor =
        new DocumentumAdaptor(proxyCls.getProxyClientX());

    String folder = "/Folder2/doesNotExist";

    Request req = proxyCls.getProxyRequest(new DocId(folder));
    Response resp = proxyCls.getProxyResponse();
    IDfSessionManager sessionManager = proxyCls.getProxySessionManager();

    adaptor.getDocContentHelper(req, resp, sessionManager,
        ProxyAdaptorContext.getInstance().getDocIdEncoder(),
        ImmutableList.of("/Folder2"), null);

    assertTrue(proxyCls.respNotFound);
  }

  @Test
  public void testGetDocContentNotUnderStartPath() throws Exception {
    FolderDocContentTestProxies proxyCls = new FolderDocContentTestProxies();
    DocumentumAdaptor adaptor =
        new DocumentumAdaptor(proxyCls.getProxyClientX());

    String path1 = "/Folder1/path1";
    String path2 = "/Folder2/path2";

    addFolder(proxyCls, "0b01081f80078d29", path1);
    addFolder(proxyCls, "0b01081f80078d30", path2);

    Request req = proxyCls.getProxyRequest(new DocId(path2));
    Response resp = proxyCls.getProxyResponse();
    IDfSessionManager sessionManager = proxyCls.getProxySessionManager();

    adaptor.getDocContentHelper(req, resp, sessionManager,
        ProxyAdaptorContext.getInstance().getDocIdEncoder(),
        ImmutableList.of("/Folder1"), null); // Folder2 not included.

    assertTrue(proxyCls.respNotFound);
  }

  /* Mock proxy classes for testing ACLs */
  private class AclTestProxies {
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
            new ACLMock(id.toString()));
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

    public class ACLMock {
      private String id;
      List<AccessorInfo> accessorList = new ArrayList<AccessorInfo>();

      public ACLMock(String id) {
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

      void grantPermit(IDfPermit permit) throws SQLException {
        jdbcFixture.executeUpdate(String.format(
            "insert into dm_acl(r_object_id, r_accessor_name, "
                + "r_accessor_permit, r_permit_type, r_is_group) values("
                + "'%s', '%s', '%s', '%s', '%s')",
            id, permit.getAccessorName(), permit.getPermitValueInt(),
            permit.getPermitType(), isAccessorGroup(permit.getAccessorName())));

        accessorList.add(new AccessorInfo(permit.getAccessorName(),
            permit.getPermitType(), permit.getPermitValueInt(),
            isAccessorGroup(permit.getAccessorName())));
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
    jdbcFixture.executeUpdate(String.format(
        "insert into dm_user(user_name, user_login_name, r_is_group) "
        + "values('%s', '%s', TRUE)", groupName, groupName));
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
    jdbcFixture.executeUpdate(String.format(
        "insert into dm_group(group_name, users_names, groups_names) "
        + "values('%s', '%s', '%s')", groupName, joiner.join(users),
        joiner.join(groups)));
  }

  private void createAcl(String id) throws SQLException {
    jdbcFixture.executeUpdate(String.format(
        "insert into dm_acl(r_object_id) values('%s')", id));
  }

  private void addAllowPermitToAcl(AclTestProxies.ACLMock aclObj, String name,
      int permit) throws SQLException {
    IDfPermit permitobj = new DfPermit();
    permitobj.setAccessorName(name);
    permitobj.setPermitType(IDfPermitType.ACCESS_PERMIT);
    permitobj.setPermitValue(Integer.toString(permit));

    aclObj.grantPermit(permitobj);
  }

  private void addDenyPermitToAcl(AclTestProxies.ACLMock aclObj, String name,
      int permit) throws SQLException {
    IDfPermit permitobj = new DfPermit();
    permitobj.setAccessorName(name);
    permitobj.setPermitType(IDfPermitType.ACCESS_RESTRICTION);
    permitobj.setPermitValue(Integer.toString(permit));

    aclObj.grantPermit(permitobj);
  }

  // tests for ACLs
  // TODO: (Srinivas) -  Add a unit test and perform manual test of
  //                     user and group names with quotes in them.
  @Test
  public void testAcls() throws Exception {
    AclTestProxies proxyCls = new AclTestProxies();
    Config config = getTestAdaptorConfig();
    createAcl("4501081f80000100");
    createAcl("4501081f80000101");
    createAcl("4501081f80000102");
    Map<DocId, Acl> namedResources = getAllAcls(proxyCls, config);

    assertEquals(3, namedResources.size());
  }

  @Test
  public void testAllowAcls() throws Exception {
    AclTestProxies proxyCls = new AclTestProxies();
    Config config = getTestAdaptorConfig();

    insertUsers("User1", "User2", "User3", "User4", "User5");
    createAcl("4501081f80000100");
    AclTestProxies.ACLMock aclObj = proxyCls.new ACLMock("4501081f80000100");
    addAllowPermitToAcl(aclObj, "User4", IDfACL.DF_PERMIT_WRITE);
    addAllowPermitToAcl(aclObj, "User5", IDfACL.DF_PERMIT_READ);
    addDenyPermitToAcl(aclObj, "User1", IDfACL.DF_PERMIT_DELETE);
    addDenyPermitToAcl(aclObj, "User2", IDfACL.DF_PERMIT_BROWSE);
    addDenyPermitToAcl(aclObj, "User3", IDfACL.DF_PERMIT_WRITE);

    Map<DocId, Acl> namedResources = getAllAcls(proxyCls, config);
    Acl acl = namedResources.get(new DocId("4501081f80000100"));
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
    AclTestProxies proxyCls = new AclTestProxies();
    Config config = getTestAdaptorConfig();

    insertUsers("User1", "User2", "User3", "User4", "User5");
    createAcl("4501081f80000100");
    AclTestProxies.ACLMock aclObj = proxyCls.new ACLMock("4501081f80000100");
    addAllowPermitToAcl(aclObj, "User4", IDfACL.DF_PERMIT_WRITE);
    addAllowPermitToAcl(aclObj, "User5", IDfACL.DF_PERMIT_READ);
    addDenyPermitToAcl(aclObj, "User1", IDfACL.DF_PERMIT_DELETE);
    addDenyPermitToAcl(aclObj, "User2", IDfACL.DF_PERMIT_BROWSE);
    addDenyPermitToAcl(aclObj, "User3", IDfACL.DF_PERMIT_WRITE);

    Map<DocId, Acl> namedResources = getAllAcls(proxyCls, config);
    Acl acl = namedResources.get(new DocId("4501081f80000100"));
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
    AclTestProxies proxyCls = new AclTestProxies();
    Config config = getTestAdaptorConfig();

    insertUsers("User1", "User2");
    insertGroup("Group1", "User2", "User3");
    insertGroup("Group2", "User4", "User5");
    insertGroup("Group3", "User6", "User7");
    createAcl("4501081f80000101");
    AclTestProxies.ACLMock aclObj = proxyCls.new ACLMock("4501081f80000101");
    addAllowPermitToAcl(aclObj, "User1", IDfACL.DF_PERMIT_WRITE);
    addAllowPermitToAcl(aclObj, "User2", IDfACL.DF_PERMIT_READ);
    addAllowPermitToAcl(aclObj, "Group1", IDfACL.DF_PERMIT_READ);
    addAllowPermitToAcl(aclObj, "Group2", IDfACL.DF_PERMIT_WRITE);
    addDenyPermitToAcl(aclObj, "Group3", IDfACL.DF_PERMIT_READ);

    Map<DocId, Acl> namedResources = getAllAcls(proxyCls, config);
    Acl acl = namedResources.get(new DocId("4501081f80000101"));
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
    AclTestProxies proxyCls = new AclTestProxies();
    Config config = getTestAdaptorConfig();

    insertUsers("User1", "User3");
    insertGroup("Group1", "User2", "User3");
    insertGroup("dm_world", "User1", "User2", "User3");
    createAcl("4501081f80000102");
    AclTestProxies.ACLMock aclObj = proxyCls.new ACLMock("4501081f80000102");
    addAllowPermitToAcl(aclObj, "Group1", IDfACL.DF_PERMIT_BROWSE);
    addAllowPermitToAcl(aclObj, "dm_world", IDfACL.DF_PERMIT_READ);
    addDenyPermitToAcl(aclObj, "User1", IDfACL.DF_PERMIT_READ);
    addDenyPermitToAcl(aclObj, "User3", IDfACL.DF_PERMIT_WRITE);

    Map<DocId, Acl> namedResources = getAllAcls(proxyCls, config);
    Acl acl = namedResources.get(new DocId("4501081f80000102"));
    assertEquals(ImmutableSet.of(new GroupPrincipal("dm_world", "localNS")),
        acl.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl.getDenyGroups());
    assertEquals(ImmutableSet.of(), acl.getPermitUsers());
    assertEquals(ImmutableSet.of(new UserPrincipal("User1", "globalNS")),
        acl.getDenyUsers());
  }

  @Test
  public void testDomainForAclUser() throws Exception {
    AclTestProxies proxyCls = new AclTestProxies();
    Config config = getTestAdaptorConfig();
    config.overrideKey("documentum.windowsDomain", "ajax");

    insertUsers("User1", "User2", "User3", "User4", "User5");
    createAcl("4501081f80000100");
    AclTestProxies.ACLMock aclObj = proxyCls.new ACLMock("4501081f80000100");
    addAllowPermitToAcl(aclObj, "User4", IDfACL.DF_PERMIT_WRITE);
    addAllowPermitToAcl(aclObj, "User5", IDfACL.DF_PERMIT_READ);
    addDenyPermitToAcl(aclObj, "User1", IDfACL.DF_PERMIT_DELETE);
    addDenyPermitToAcl(aclObj, "User2", IDfACL.DF_PERMIT_BROWSE);
    addDenyPermitToAcl(aclObj, "User3", IDfACL.DF_PERMIT_WRITE);

    Map<DocId, Acl> namedResources = getAllAcls(proxyCls, config);

    Acl acl = namedResources.get(new DocId("4501081f80000100"));
    assertEquals(ImmutableSet.of(new UserPrincipal("ajax\\User4", "globalNS"),
        new UserPrincipal("ajax\\User5", "globalNS")),
        acl.getPermitUsers());
    assertEquals(ImmutableSet.of(new UserPrincipal("ajax\\User2", "globalNS")),
        acl.getDenyUsers());
  }

  @Test
  public void testDnsDomainForAclUser() throws Exception {
    AclTestProxies proxyCls = new AclTestProxies();
    Config config = getTestAdaptorConfig();
    config.overrideKey("documentum.windowsDomain", "ajax.example.com");

    insertUsers("User1", "User2", "User3", "User4", "User5");
    createAcl("4501081f80000100");
    AclTestProxies.ACLMock aclObj = proxyCls.new ACLMock("4501081f80000100");
    addAllowPermitToAcl(aclObj, "User4", IDfACL.DF_PERMIT_WRITE);
    addAllowPermitToAcl(aclObj, "User5", IDfACL.DF_PERMIT_READ);
    addDenyPermitToAcl(aclObj, "User1", IDfACL.DF_PERMIT_DELETE);
    addDenyPermitToAcl(aclObj, "User2", IDfACL.DF_PERMIT_BROWSE);
    addDenyPermitToAcl(aclObj, "User3", IDfACL.DF_PERMIT_WRITE);

    Map<DocId, Acl> namedResources = getAllAcls(proxyCls, config);
    Acl acl = namedResources.get(new DocId("4501081f80000100"));
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
    AclTestProxies proxyCls = new AclTestProxies();
    Config config = getTestAdaptorConfig();
    config.overrideKey("documentum.windowsDomain", "ajax");

    insertUsers("User1", "User2");
    insertGroup("Group1", "User2", "User3");
    insertGroup("Group2", "User4", "User5");
    insertGroup("Group3", "User6", "User7");
    createAcl("4501081f80000101");
    AclTestProxies.ACLMock aclObj = proxyCls.new ACLMock("4501081f80000101");
    addAllowPermitToAcl(aclObj, "User1", IDfACL.DF_PERMIT_WRITE);
    addAllowPermitToAcl(aclObj, "User2", IDfACL.DF_PERMIT_READ);
    addAllowPermitToAcl(aclObj, "Group1", IDfACL.DF_PERMIT_READ);
    addAllowPermitToAcl(aclObj, "Group2", IDfACL.DF_PERMIT_WRITE);
    addDenyPermitToAcl(aclObj, "Group3", IDfACL.DF_PERMIT_READ);

    Map<DocId, Acl> namedResources = getAllAcls(proxyCls, config);
    Acl acl = namedResources.get(new DocId("4501081f80000101"));
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group1", "localNS"),
        new GroupPrincipal("Group2", "localNS")),
        acl.getPermitGroups());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group3", "localNS")),
        acl.getDenyGroups());
  }

  // Tests for required groups and required group sets.
  private void addRequiredGroupSetToAcl(AclTestProxies.ACLMock aclObj,
      String name) throws SQLException {
    IDfPermit permitobj = new DfPermit();
    permitobj.setAccessorName(name);
    permitobj.setPermitType(IDfPermitType.REQUIRED_GROUP_SET);
    aclObj.grantPermit(permitobj);
  }

  private void addRequiredGroupToAcl(AclTestProxies.ACLMock aclObj, String name)
      throws SQLException {
    IDfPermit permitobj = new DfPermit();
    permitobj.setAccessorName(name);
    permitobj.setPermitType(IDfPermitType.REQUIRED_GROUP);
    aclObj.grantPermit(permitobj);
  }

  @Test
  public void testRequiredGroupSetAcl() throws DfException,
      InterruptedException, SQLException {
    AclTestProxies proxyCls = new AclTestProxies();
    Config config = getTestAdaptorConfig();

    insertUsers("User1", "User2", "User3", "User4", "User5", "User6", "User7");
    insertGroup("Group1", "User2", "User3");
    insertGroup("Group2", "User4", "User5");
    insertGroup("Group3", "User6", "User7");
    insertGroup("GroupSet1", "Group1", "Group2");
    insertGroup("GroupSet2", "Group2", "Group3");
   
    createAcl("4501081f80000103");
    AclTestProxies.ACLMock aclObj = proxyCls.new ACLMock("4501081f80000103");
    addAllowPermitToAcl(aclObj, "Group1", IDfACL.DF_PERMIT_READ);
    addAllowPermitToAcl(aclObj, "Group2", IDfACL.DF_PERMIT_WRITE);
    addDenyPermitToAcl(aclObj, "Group3", IDfACL.DF_PERMIT_READ);
    addRequiredGroupSetToAcl(aclObj, "GroupSet1");
    addRequiredGroupSetToAcl(aclObj, "GroupSet2");

    Map<DocId, Acl> namedResources = getAllAcls(proxyCls, config);
    assertEquals(2, namedResources.size());

    Acl acl1 = namedResources.get(new DocId("4501081f80000103_reqGroupSet"));
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl1.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("GroupSet1", "localNS"),
        new GroupPrincipal("GroupSet2", "localNS")),
        acl1.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl1.getDenyGroups());

    Acl acl2 = namedResources.get(new DocId("4501081f80000103"));
    assertEquals(new DocId("4501081f80000103_reqGroupSet"),
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
    AclTestProxies proxyCls = new AclTestProxies();
    Config config = getTestAdaptorConfig();

    insertUsers("User1", "User2", "User3", "User4", "User5", "User6", "User7");
    insertGroup("Group1", "User2", "User3");
    insertGroup("Group2", "User4", "User5");
    insertGroup("Group3", "User6", "User7");
    insertGroup("Group4", "User2", "User3");
    insertGroup("Group5", "User4", "User5");
    insertGroup("Group6", "User6", "User7");

    createAcl("4501081f80000104");
    AclTestProxies.ACLMock aclObj = proxyCls.new ACLMock("4501081f80000104");
    addAllowPermitToAcl(aclObj, "Group1", IDfACL.DF_PERMIT_READ);
    addAllowPermitToAcl(aclObj, "Group2", IDfACL.DF_PERMIT_WRITE);
    addDenyPermitToAcl(aclObj, "Group3", IDfACL.DF_PERMIT_READ);
    addRequiredGroupToAcl(aclObj, "Group4");
    addRequiredGroupToAcl(aclObj, "Group5");
    addRequiredGroupToAcl(aclObj, "Group6");

    Map<DocId, Acl> namedResources = getAllAcls(proxyCls, config);
    assertEquals(4, namedResources.size());

    Acl acl1 = namedResources.get(new DocId("4501081f80000104_Group6"));
    assertEquals(new DocId("4501081f80000104_Group5"), acl1.getInheritFrom());
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl1.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group6", "localNS")),
        acl1.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl1.getDenyGroups());

    Acl acl2 = namedResources.get(new DocId("4501081f80000104_Group5"));
    assertEquals(new DocId("4501081f80000104_Group4"), acl2.getInheritFrom());
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl2.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group5", "localNS")),
        acl2.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl2.getDenyGroups());

    Acl acl3 = namedResources.get(new DocId("4501081f80000104_Group4"));
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl3.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group4", "localNS")),
        acl3.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl3.getDenyGroups());

    Acl acl4 = namedResources.get(new DocId("4501081f80000104"));
    assertEquals(new DocId("4501081f80000104_Group6"), acl4.getInheritFrom());
    assertEquals(InheritanceType.PARENT_OVERRIDES, acl4.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group1", "localNS"),
        new GroupPrincipal("Group2", "localNS")),
        acl4.getPermitGroups());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group3", "localNS")),
        acl4.getDenyGroups());
  }

  @Test
  public void testRequiredGroupsAndSetsAcl() throws Exception {
    AclTestProxies proxyCls = new AclTestProxies();
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

    createAcl("4501081f80000105");
    AclTestProxies.ACLMock aclObj = proxyCls.new ACLMock("4501081f80000105");
    addAllowPermitToAcl(aclObj, "Group1", IDfACL.DF_PERMIT_READ);
    addAllowPermitToAcl(aclObj, "Group2", IDfACL.DF_PERMIT_WRITE);
    addDenyPermitToAcl(aclObj, "Group3", IDfACL.DF_PERMIT_READ);
    addRequiredGroupToAcl(aclObj, "Group4");
    addRequiredGroupToAcl(aclObj, "Group5");
    addRequiredGroupToAcl(aclObj, "Group6");
    addRequiredGroupSetToAcl(aclObj, "GroupSet1");
    addRequiredGroupSetToAcl(aclObj, "GroupSet2");

    Map<DocId, Acl> namedResources = getAllAcls(proxyCls, config);
    assertEquals(5, namedResources.size());

    Acl acl1 = namedResources.get(new DocId("4501081f80000105_Group6"));
    assertEquals(new DocId("4501081f80000105_Group5"), acl1.getInheritFrom());
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl1.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group6", "localNS")),
        acl1.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl1.getDenyGroups());

    Acl acl2 = namedResources.get(new DocId("4501081f80000105_Group5"));
    assertEquals(new DocId("4501081f80000105_Group4"), acl2.getInheritFrom());
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl2.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group5", "localNS")),
        acl2.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl2.getDenyGroups());

    Acl acl3 = namedResources.get(new DocId("4501081f80000105_Group4"));
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl3.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group4", "localNS")),
        acl3.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl3.getDenyGroups());

    Acl acl4 = namedResources.get(new DocId("4501081f80000105_reqGroupSet"));
    assertEquals(new DocId("4501081f80000105_Group6"), acl4.getInheritFrom());
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl4.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("GroupSet1", "localNS"),
        new GroupPrincipal("GroupSet2", "localNS")),
        acl4.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl4.getDenyGroups());

    Acl acl5 = namedResources.get(new DocId("4501081f80000105"));
    assertEquals(new DocId("4501081f80000105_reqGroupSet"),
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
    AclTestProxies proxyCls = new AclTestProxies();
    Config config = getTestAdaptorConfig();

    insertUsers("User1", "User2", "User3");
    insertGroup("Group1", "User2", "User3");

    createAcl("4501081f80000104");
    AclTestProxies.ACLMock aclObj = proxyCls.new ACLMock("4501081f80000104");
    addAllowPermitToAcl(aclObj, "Group1", IDfACL.DF_PERMIT_READ);
    addRequiredGroupToAcl(aclObj, "GroupNotExists");

    Map<DocId, Acl> namedResources = getAllAcls(proxyCls, config);
    assertEquals(2, namedResources.size());

    // TODO(srinivas): non-existent groups should be dropped from the ACL?
    Acl acl1 = namedResources.get(new DocId("4501081f80000104_GroupNotExists"));
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl1.getInheritanceType());
    assertEquals(
        ImmutableSet.of(new GroupPrincipal("GroupNotExists", "localNS")),
        acl1.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl1.getDenyGroups());

    Acl acl2 = namedResources.get(new DocId("4501081f80000104"));
    assertEquals(new DocId("4501081f80000104_GroupNotExists"),
        acl2.getInheritFrom());
    assertEquals(InheritanceType.PARENT_OVERRIDES, acl2.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group1", "localNS")),
        acl2.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl2.getDenyGroups());
  }

  /* TODO(bmj): This should create the adaptor, init it with config, then call
   * its getDocIds method with a recording pusher and return the pushed acls.
   */
  private Map<DocId, Acl> getAllAcls(AclTestProxies proxyCls, Config config)
      throws DfException {
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

  /* Mock proxy classes for testing pushing Groups */
  private class GroupTestProxies {
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
        return getRepeatingValue(colName)[index].trim();
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
  }

  @Test
  public void testGetGroupsDmWorldOnly() throws Exception {
    GroupTestProxies proxyCls = new GroupTestProxies();
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

    Map<GroupPrincipal, Collection<Principal>> groups =
        getGroups(proxyCls, config);

    assertEquals(expected, groups);
  }

  @Test
  public void testGetGroupsUserMembersOnly() throws Exception {
    GroupTestProxies proxyCls = new GroupTestProxies();
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

    Map<GroupPrincipal, Collection<Principal>> groups =
        getGroups(proxyCls, config);

    assertEquals(expected, filterDmWorld(groups));
  }

  @Test
  public void testGetGroupsInvalidMembers() throws Exception {
    GroupTestProxies proxyCls = new GroupTestProxies();
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

    Map<GroupPrincipal, Collection<Principal>> groups =
        getGroups(proxyCls, config);

    assertEquals(expected, filterDmWorld(groups));
  }

  @Test
  public void testGetGroupsEmptyGroup() throws Exception {
    GroupTestProxies proxyCls = new GroupTestProxies();
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

    Map<GroupPrincipal, Collection<Principal>> groups =
        getGroups(proxyCls, config);

    assertEquals(expected, filterDmWorld(groups));
  }

  @Test
  public void testGetGroupsUserAndGroupMembers() throws Exception {
    GroupTestProxies proxyCls = new GroupTestProxies();
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

    Map<GroupPrincipal, Collection<Principal>> groups =
        getGroups(proxyCls, config);

    assertEquals(expected, filterDmWorld(groups));
  }

  @Test
  public void testGetGroupsDifferentMemberLoginName() throws Exception {
    GroupTestProxies proxyCls = new GroupTestProxies();
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

    Map<GroupPrincipal, Collection<Principal>> groups =
        getGroups(proxyCls, config);

    assertEquals(expected, filterDmWorld(groups));
  }

  @Test
  public void testGetGroupsDifferentGroupLoginName() throws Exception {
    GroupTestProxies proxyCls = new GroupTestProxies();
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

    Map<GroupPrincipal, Collection<Principal>> groups =
        getGroups(proxyCls, config);

    assertEquals(expected, filterDmWorld(groups));
  }

  @Test
  public void testGetGroupsMemberLdapDn() throws Exception {
    GroupTestProxies proxyCls = new GroupTestProxies();
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

    Map<GroupPrincipal, Collection<Principal>> groups =
        getGroups(proxyCls, config);

    assertEquals(expected, filterDmWorld(groups));
  }

  @Test
  public void testGetGroupsGroupLdapDn() throws Exception {
    GroupTestProxies proxyCls = new GroupTestProxies();
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

    Map<GroupPrincipal, Collection<Principal>> groups =
        getGroups(proxyCls, config);

    assertEquals(expected, filterDmWorld(groups));
  }

  @Test
  public void testGetGroupsWindowsDomainUsers() throws Exception {
    GroupTestProxies proxyCls = new GroupTestProxies();
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

    Map<GroupPrincipal, Collection<Principal>> groups =
        getGroups(proxyCls, config);

    assertEquals(expected, filterDmWorld(groups));
  }

  @Test
  public void testGetGroupsLocalAndGlobalGroups() throws Exception {
    GroupTestProxies proxyCls = new GroupTestProxies();
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

    Map<GroupPrincipal, Collection<Principal>> groups =
        getGroups(proxyCls, config);

    assertEquals(expected, filterDmWorld(groups));
  }

  @Test
  public void testGetGroupsGlobalGroupMembers() throws Exception {
    GroupTestProxies proxyCls = new GroupTestProxies();
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

    Map<GroupPrincipal, Collection<Principal>> groups =
        getGroups(proxyCls, config);

    assertEquals(expected, filterDmWorld(groups));
  }

  @Test
  public void testGetGroupsLocalGroupsOnly() throws Exception {
    GroupTestProxies proxyCls = new GroupTestProxies();
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

    Map<GroupPrincipal, Collection<Principal>> groups =
        getGroups(proxyCls, config);

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
    jdbcFixture.executeUpdate(String.format("insert into dm_user("
        + "user_name, user_login_name, user_source, user_ldap_dn, r_is_group) "
        + "values('%s', '%s', 'LDAP', '%s', TRUE)", groupName, groupName,
        "CN=" + groupName));
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
    jdbcFixture.executeUpdate(String.format("insert into dm_group("
        + "group_name, group_source, users_names, groups_names) "
        + "values('%s', 'LDAP', '%s', '%s')", groupName, joiner.join(users),
        joiner.join(groups)));
  }

  /* TODO(bmj): This should create the adaptor, init it with config, then call
   * its getDocIds method with a recording pusher and return the pushed groups.
   */
  private Map<GroupPrincipal, Collection<Principal>> getGroups(
      GroupTestProxies proxyCls, Config config) throws DfException {
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


  /* Mock proxy classes for testing ACL Updates */
  private class AclUpdateTestProxies {
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
          throws SQLException {
        return Proxies.newProxyInstance(IDfCollection.class,
            new CollectionMock(query));
      }
    }

    private class CollectionMock {
      Statement stmt;
      ResultSet rs;

      public CollectionMock(String query) throws SQLException {
        stmt = jdbcFixture.getConnection().createStatement();
        query = query.replace("DATETOSTRING", "FORMATDATETIME")
            .replace("date(", "parseDateTime(")
            .replace("yyyy-mm-dd hh:mi:ss", DocumentumAcls.DATE_FORMAT);
        rs = stmt.executeQuery(query);
      }

      public String getString(String colName) throws SQLException {
        return rs.getString(colName);
      }

      public boolean next() throws SQLException {
        return rs.next();
      }

      public int getState() {
        return IDfCollection.DF_READY_STATE;
      }

      public void close() throws SQLException {
        rs.close();
        stmt.close();
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
            new ACLMock(id.toString()));
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

    public class ACLMock {
      private String id;
      List<AccessorInfo> accessorList = new ArrayList<AccessorInfo>();

      public ACLMock(String id) {
        this.id = id;
        try {
          getAccessorInfo();
        } catch (SQLException e) {
          e.printStackTrace();
        }
      }

      private void getAccessorInfo() throws SQLException {
        Statement stmt = null;
        ResultSet rs = null;
        try {
          stmt = jdbcFixture.getConnection().createStatement();
          rs = stmt.executeQuery("select r_accessor_name,  r_accessor_permit, "
              + "r_permit_type, r_is_group from dm_acl "
              + "where r_object_id = '" + id + "'");
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
        } finally {
          rs.close();
          stmt.close();
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

      private boolean isAccessorGroup(String accessorName) throws SQLException {
        Statement stmt = null;
        ResultSet rs = null;
        try {
          stmt = jdbcFixture.getConnection().createStatement();
          rs = stmt.executeQuery("select r_is_group from dm_user"
              + " where user_name = '" + accessorName + "'");
          if (rs.next()) {
            return rs.getBoolean(1);
          }
        } finally {
          rs.close();
          stmt.close();
        }
        return false;
      }

      void grantPermit(IDfPermit permit) throws SQLException {
        jdbcFixture.executeUpdate(String.format(
            "insert into dm_acl(r_object_id, r_accessor_name, "
                + "r_accessor_permit, r_permit_type, r_is_group) values("
                + "'%s', '%s', '%s', '%s', '%s')",
            id, permit.getAccessorName(), permit.getPermitValueInt(),
            permit.getPermitType(), isAccessorGroup(permit.getAccessorName())));

        accessorList.add(new AccessorInfo(permit.getAccessorName(),
            permit.getPermitType(), permit.getPermitValueInt(),
            isAccessorGroup(permit.getAccessorName())));
      }
    }
  }

  private void insertAclAudit(String id, String chronicleId, String auditObjId,
      String eventName, String date) throws SQLException {
    jdbcFixture.executeUpdate(String.format(
        "insert into dm_audittrail_acl(r_object_id, chronicle_id, "
            + "audited_obj_id, event_name, time_stamp_utc) "
            + "values('%s', '%s', '%s', '%s', convert(parseDateTime('%s', "
            + "'yyyy-MM-dd hh:mm:ss'), timestamp))",
            id, chronicleId, auditObjId, eventName, date));
  }

  private DocumentumAcls getDocumentumAcls() throws DfException {
    AclUpdateTestProxies proxyCls = new AclUpdateTestProxies();
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

  @Test
  public void testUpdateAcls() throws Exception {
    createAcl("4501081f80000100");
    createAcl("4501081f80000101");
    createAcl("4501081f80000102");
    String dateStr = getNowPlusMinutes(5);
    insertAclAudit("123", "234", "4501081f80000100", "dm_save", dateStr);
    insertAclAudit("124", "235", "4501081f80000101", "dm_saveasnew", dateStr);
    insertAclAudit("125", "236", "4501081f80000102", "dm_destroy", dateStr);

    Map<DocId, Acl> aclMap = getDocumentumAcls().getUpdateAcls();
    assertEquals(ImmutableSet.of(
        new DocId("4501081f80000100"),
        new DocId("4501081f80000101"),
        new DocId("4501081f80000102")), aclMap.keySet());

    Acl acl = aclMap.get(new DocId("4501081f80000100"));
    assertTrue(acl.getPermitUsers().isEmpty());
  }

  @Test
  public void testUpdateAclsWithSameChronicleId() throws Exception {
    createAcl("4501081f80000100");
    createAcl("4501081f80000101");
    createAcl("4501081f80000102");
    String dateStr = getNowPlusMinutes(6);
    insertAclAudit("123", "234", "4501081f80000100", "dm_save", dateStr);
    insertAclAudit("124", "234", "4501081f80000101", "dm_saveasnew", dateStr);
    insertAclAudit("125", "234", "4501081f80000102", "dm_destroy", dateStr);

    Map<DocId, Acl> aclMap = getDocumentumAcls().getUpdateAcls();
    assertEquals(ImmutableSet.of(new DocId("4501081f80000100")),
        aclMap.keySet());
  }

  @Test
  public void testPreviouslyUpdatedAcls() throws Exception {
    createAcl("4501081f80000100");
    createAcl("4501081f80000101");
    createAcl("4501081f80000102");
    String dateStr = getNowPlusMinutes(-10);
    insertAclAudit("123", "234", "4501081f80000100", "dm_save", dateStr);
    insertAclAudit("124", "235", "4501081f80000101", "dm_saveasnew", dateStr);
    insertAclAudit("125", "236", "4501081f80000102", "dm_destroy", dateStr);

    Map<DocId, Acl> aclMap = getDocumentumAcls().getUpdateAcls();
    assertEquals(ImmutableMap.of(), aclMap);
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

    Map<DocId, Acl> aclMap = dctmAcls.getUpdateAcls();
    assertEquals(ImmutableSet.of(
        new DocId("4501081f80000100"),
        new DocId("4501081f80000101"),
        new DocId("4501081f80000102")), aclMap.keySet());

    dateStr = getNowPlusMinutes(15);
    insertAclAudit("126", "237", "4501081f80000103", "dm_saveasnew", dateStr);
    insertAclAudit("127", "238", "4501081f80000104", "dm_destroy", dateStr);

    aclMap = dctmAcls.getUpdateAcls();
    assertEquals(ImmutableSet.of(
        new DocId("4501081f80000103"), 
        new DocId("4501081f80000104")), aclMap.keySet());
  }

  @Test
  public void testMultiUpdateAclsWithNoResults() throws Exception {
    DocumentumAcls dctmAcls = getDocumentumAcls();

    createAcl("4501081f80000106");
    createAcl("4501081f80000107");
    String dateStr = getNowPlusMinutes(20);
    insertAclAudit("128", "234", "4501081f80000106", "dm_saveasnew", dateStr);
    insertAclAudit("129", "235", "4501081f80000107", "dm_saveasnew", dateStr);

    Map<DocId, Acl> aclMap = dctmAcls.getUpdateAcls();
    assertEquals(ImmutableSet.of(
        new DocId("4501081f80000106"),
        new DocId("4501081f80000107")), aclMap.keySet());

    aclMap = dctmAcls.getUpdateAcls();
    assertEquals(ImmutableSet.of(), aclMap.keySet());
  }

  /**
   * Returns date string with minutes added to current time.
   *
   * @param minutes minutes to add.
   * @return date in string format.
   */
  private String getNowPlusMinutes(int minutes) {
    SimpleDateFormat format = new SimpleDateFormat(DocumentumAcls.DATE_FORMAT);
    Calendar calendar = Calendar.getInstance();
    calendar.add(Calendar.MINUTE, minutes);
    return format.format(calendar.getTime());
  }
}
