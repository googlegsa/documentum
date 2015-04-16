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

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Multimap;
import com.google.common.collect.Multimaps;
import com.google.common.collect.TreeMultimap;
import com.google.enterprise.adaptor.AdaptorContext;
import com.google.enterprise.adaptor.Config;
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.Request;
import com.google.enterprise.adaptor.Response;

import com.documentum.com.IDfClientX;
import com.documentum.fc.client.IDfClient;
import com.documentum.fc.client.IDfCollection;
import com.documentum.fc.client.IDfFolder;
import com.documentum.fc.client.IDfSession;
import com.documentum.fc.client.IDfSessionManager;
import com.documentum.fc.client.IDfSysObject;
import com.documentum.fc.client.IDfType;
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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
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
      + "(group_name varchar, i_all_users_names varchar)";

  private static final String CREATE_TABLE_USER = "create table dm_user "
      + "(user_name varchar primary key, user_login_name varchar, "
      + "user_source varchar, user_ldap_dn varchar, r_is_group boolean)";

  private JdbcFixture jdbcFixture = new JdbcFixture();

  @Before
  public void setUp() throws Exception {
    jdbcFixture.executeUpdate(CREATE_TABLE_GROUP, CREATE_TABLE_USER);
  }

  @After
  public void tearDown() throws Exception {
    jdbcFixture.tearDown();
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
    Config config = context.getConfig();
    config.addKey("documentum.username", "testuser");
    config.addKey("documentum.password", "testpwd");
    config.addKey("documentum.docbaseName", "testdocbase");
    config.addKey("documentum.src", "/Folder1/path1");
    config.addKey("documentum.separatorRegex", ",");
    config.addKey("documentum.excludedAttributes", "foo, bar");

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
    Config config = context.getConfig();
    config.addKey("documentum.username", "testuser");
    config.addKey("documentum.password", "testpwd");
    config.addKey("documentum.docbaseName", "testdocbase");
    config.addKey("documentum.src", "/Folder1/path1, /Folder2/path2,"
        + "/Folder3/path3");
    config.addKey("documentum.separatorRegex", ",");
    config.addKey("documentum.excludedAttributes", "foo, bar");

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
    Config config = context.getConfig();
    config.addKey("documentum.username", "testuser");
    config.addKey("documentum.password", "testpwd");
    config.addKey("documentum.docbaseName", "testdocbase");
    config.addKey("documentum.separatorRegex", ",");
    config.addKey("documentum.excludedAttributes", "foo, bar");

    String startPaths = paths[0];
    for (int i = 1; i < paths.length; i++) {
      startPaths = startPaths + "," + paths[i];
    }
    config.addKey("documentum.src", startPaths);

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
    assertFalse(adaptor.getValidatedStartPaths().contains(path4));
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
    assertFalse(adaptor.getValidatedStartPaths().contains(path1));
    assertFalse(adaptor.getValidatedStartPaths().contains(path2));
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
  public void testDocContent() throws DfException, IOException {
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
  public void testSingleValueMetadata() throws DfException, IOException {
    TreeMultimap<String, String> attributes = TreeMultimap.create();
    attributes.put("attr1", "value1");
    attributes.put("attr2", "value2");
    attributes.put("attr3", "value3");
    testMetadata(attributes, attributes);
  }

  @Test
  public void testMultiValueMetadata() throws DfException, IOException {
    TreeMultimap<String, String> attributes = TreeMultimap.create();
    attributes.put("attr1", "value1");
    attributes.put("attr1", "value2");
    attributes.put("attr1", "value3");
    assertEquals(1, attributes.keySet().size());
    assertEquals(3, attributes.get("attr1").size());
    testMetadata(attributes, attributes);
  }

  @Test
  public void testEmptyValueMetadata() throws DfException, IOException {
    TreeMultimap<String, String> attributes = TreeMultimap.create();
    attributes.put("attr1", "value1");
    attributes.put("attr2", "value2");
    attributes.put("attr2", "");
    attributes.put("attr3", "");
    testMetadata(attributes, attributes);
  }

  @Test
  public void testExcludeAttrMetadata() throws DfException, IOException {
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
      TreeMultimap<String, String> expected) throws DfException, IOException {
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
  public void testFolderDocContent() throws DfException, IOException {
    FolderDocContentTestProxies proxyCls = new FolderDocContentTestProxies();
    DocumentumAdaptor adaptor =
        new DocumentumAdaptor(proxyCls.getProxyClientX());

    String folder = "/Folder2/subfolder/path2";

    Request req = proxyCls.getProxyRequest(adaptor.docIdFromPath(folder));
    Response resp = proxyCls.getProxyResponse();
    IDfSessionManager sessionManager = proxyCls.getProxySessionManager();

    addFolder(proxyCls, "0b01081f80078d29", folder);
    StringBuffer expected = new StringBuffer();
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
  public void testGetDocContentNotFound() throws DfException, IOException {
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
  public void testGetDocContentNotUnderStartPath()
      throws DfException, IOException {
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
}
