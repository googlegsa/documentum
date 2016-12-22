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

import static com.google.enterprise.adaptor.documentum.JdbcFixture.dropAllObjects;
import static com.google.enterprise.adaptor.documentum.JdbcFixture.executeUpdate;
import static com.google.enterprise.adaptor.documentum.JdbcFixture.getConnection;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.common.base.Joiner;
import com.google.common.base.Predicate;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterators;
import com.google.common.collect.Maps;
import com.google.common.collect.Multimap;
import com.google.common.collect.TreeMultimap;
import com.google.common.collect.UnmodifiableIterator;
import com.google.enterprise.adaptor.Acl;
import com.google.enterprise.adaptor.Acl.InheritanceType;
import com.google.enterprise.adaptor.AdaptorContext;
import com.google.enterprise.adaptor.Config;
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.DocIdEncoder;
import com.google.enterprise.adaptor.DocIdPusher;
import com.google.enterprise.adaptor.DocIdPusher.Record;
import com.google.enterprise.adaptor.GroupPrincipal;
import com.google.enterprise.adaptor.InvalidConfigurationException;
import com.google.enterprise.adaptor.Principal;
import com.google.enterprise.adaptor.Request;
import com.google.enterprise.adaptor.UserPrincipal;
import com.google.enterprise.adaptor.documentum.DocumentumAdaptor.CaseSensitivityType;
import com.google.enterprise.adaptor.documentum.DocumentumAdaptor.Checkpoint;

import com.documentum.com.IDfClientX;
import com.documentum.fc.client.DfIdNotFoundException;
import com.documentum.fc.client.DfPermit;
import com.documentum.fc.client.IDfACL;
import com.documentum.fc.client.IDfClient;
import com.documentum.fc.client.IDfCollection;
import com.documentum.fc.client.IDfEnumeration;
import com.documentum.fc.client.IDfFolder;
import com.documentum.fc.client.IDfFormat;
import com.documentum.fc.client.IDfGroup;
import com.documentum.fc.client.IDfObjectPath;
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
import org.junit.Rule;
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
import java.util.ArrayDeque;
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

// TODO(bmj): Add tests to test the exception handling.

// TODO(bmj): Add tests that call getDocIds and getModifiedDocIds with 
// expected returns for all three items: documents, groups, and ACLs.

/** Unit tests for DocumentAdaptor class. */
public class DocumentumAdaptorTest {

  private static enum LocalGroupsOnly { TRUE, FALSE };
  private static enum MarkAllDocsPublic { TRUE, FALSE };

  private static final SimpleDateFormat dateFormat =
      new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

  private static final String EPOCH_1970 = "1970-01-01 00:00:00";
  private static final String JAN_1970 = "1970-01-01 02:03:04";
  private static final String FEB_1970 = "1970-02-01 02:03:04";
  private static final String MAR_1970 = "1970-03-01 02:03:04";

  private static final String START_PATH = "/Folder1/path1";

  private static final String DEFAULT_ACL = "45DefaultACL";

  private static final String CREATE_TABLE_ACL = "create table dm_acl "
      + "(r_object_id varchar, r_accessor_name varchar, "
      + "r_accessor_permit int, r_permit_type int, r_is_group boolean)";

  private static final String CREATE_TABLE_AUDITTRAIL =
      "create table dm_audittrail "
      + "(r_object_id varchar, audited_obj_id varchar, chronicle_id varchar, "
      + "event_name varchar, time_stamp_utc timestamp, attribute_list varchar)";

  private static final String CREATE_TABLE_AUDITTRAIL_ACL =
      "create table dm_audittrail_acl "
      + "(r_object_id varchar, chronicle_id varchar, audited_obj_id varchar, "
      + "event_name varchar, time_stamp_utc timestamp)";

  private static final String CREATE_TABLE_CABINET = "create table dm_cabinet "
      + "(r_object_id varchar, r_folder_path varchar, object_name varchar, "
      + "owner_name varchar)";

  private static final String CREATE_TABLE_FOLDER = "create table dm_folder "
      // Note: mock_acl_id is ACL id for the folder, and is used to
      // create AclMock.
      + "(r_object_id varchar, r_folder_path varchar, mock_acl_id varchar)";

  private static final String CREATE_TABLE_GROUP = "create table dm_group "
      + "(r_object_id varchar, group_name varchar, group_source varchar, "
      + "groups_names varchar, users_names varchar, r_modify_date timestamp)";

  private static final String CREATE_TABLE_USER = "create table dm_user "
      + "(r_object_id varchar, user_name varchar primary key, "
      + "user_login_name varchar, user_source varchar, user_ldap_dn varchar, "
      + "r_is_group boolean, user_state int DEFAULT 0)";

  private static final String CREATE_TABLE_SYSOBJECT =
      "create table dm_sysobject "
      + "(r_object_id varchar, r_modify_date timestamp, r_object_type varchar, "
      + "object_name varchar, i_folder_id varchar, "
      + "r_is_virtual_doc boolean, r_content_size bigint, "
      // Note: mock_content ia an artifact that stores the content as a string,
      // and mock_object_path is an artifact used to emulate FOLDER predicate,
      // and to assist getObjectByPath.
      + "mock_content varchar, mock_object_path varchar, "
      // Note: mock_mime_type is an artifact that stores the mime type that
      // would actually be stored in dm_format. It is used to create FormatMock
      // in SysObjectMock.
      + "mock_mime_type varchar, "
      // Note: mock_acl_id is ACL id for the document, and is used to
      // create AclMock in SysObjectMock.
      + "mock_acl_id varchar )";

  private static final DocumentumAdaptor.Sleeper NO_SLEEP =
      new DocumentumAdaptor.Sleeper() {
        @Override public void sleep() {}
        @Override public String toString() {
          return "No sleep";
        }
      };

  private static final DfException NO_EXCEPTION = null;

  @Before
  public void setUp() throws Exception {
    Principals.clearCache();
    executeUpdate(CREATE_TABLE_ACL, CREATE_TABLE_AUDITTRAIL,
        CREATE_TABLE_AUDITTRAIL_ACL, CREATE_TABLE_CABINET, CREATE_TABLE_FOLDER,
        CREATE_TABLE_GROUP, CREATE_TABLE_SYSOBJECT, CREATE_TABLE_USER);

    // Force the default test start path to exist, so we pass init().
    insertFolder(EPOCH_1970, "0bStartPath", START_PATH);
  }

  @After
  public void tearDown() throws Exception {
    dropAllObjects();
  }

  private Config getTestAdaptorConfig() {
    return initTestAdaptorConfig(ProxyAdaptorContext.getInstance());
  }

  private Config initTestAdaptorConfig(AdaptorContext context) {
    Config config = context.getConfig();
    config.addKey("documentum.username", "testuser");
    config.addKey("documentum.password", "testpwd");
    config.addKey("documentum.docbaseName", "testdocbase");
    config.addKey("documentum.displayUrlPattern", "http://webtop/drl/{0}");
    config.addKey("documentum.src", START_PATH);
    config.addKey("documentum.src.separator", ",");
    config.addKey("documentum.documentTypes", "dm_document");
    config.addKey("documentum.indexFolders", "true");
    config.addKey("documentum.excludedAttributes", "");
    config.addKey("adaptor.namespace", "globalNS");
    config.addKey("documentum.windowsDomain", "");
    config.addKey("documentum.pushLocalGroupsOnly", "false");
    config.addKey("documentum.queryBatchSize", "0");
    config.addKey("documentum.maxHtmlSize", "1000");
    config.addKey("documentum.cabinetWhereCondition", "");
    config.addKey("adaptor.caseSensitivityType", "");
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
    initTestAdaptorConfig(context);

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
    Config config = initTestAdaptorConfig(context);
    config.overrideKey("documentum.src", "/Folder1/path1, /Folder2/path2,"
        + "/Folder3/path3");
    adaptor.init(context);

    assertEquals(Arrays.asList("/Folder1/path1", "/Folder2/path2",
        "/Folder3/path3"), adaptor.getStartPaths());
  }

  private class InitTestProxies {
    List <String> methodCallSequence = new ArrayList<String>();
    Set <String> methodCalls = new HashSet<String>();

    String serverVersion = "1.0.0.000 (Mock CS)";

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

    public void setServerVersion(String serverVersion) {
      this.serverVersion = serverVersion;
    }

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
        return serverVersion;
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

      public IDfType getType(String type) {
        return Proxies.newProxyInstance(IDfType.class, new TypeMock(type));
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

      @Override
      public String toString() {
        return objectId;
      }
    }

    private class TypeMock {
      private final String type;
      private final ImmutableMap<String, String> superTypes =
          ImmutableMap.of("dm_document", "dm_sysobject");

      public TypeMock(String type) {
        this.type = type;
      }

      public boolean isTypeOf(String otherType) {
        if (type.startsWith(otherType)) {
          return true;
        }

        String parent = superTypes.get(type);
        while (parent != null) {
          if (superTypes.get(type).startsWith(otherType)) {
            return true;
          }
          parent = superTypes.get(parent);
        }
        return false;
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
    config.overrideKey("documentum.documentTypes", "dm_document");

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
    Config config = initTestAdaptorConfig(context);
    config.overrideKey("documentum.src", Joiner.on(",").join(paths));
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

  private void testValidateDisplayUrlPattern(String pattern)
      throws DfException {
    DocumentumAdaptor adaptor =
        new DocumentumAdaptor(new InitTestProxies().getProxyClientX());
    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initTestAdaptorConfig(context);
    config.overrideKey("documentum.displayUrlPattern", pattern);
    adaptor.init(context);
  }

  @Test
  public void testValidateDisplayUrlPatternObjectId() throws DfException {
    testValidateDisplayUrlPattern("http://webtopurl/drl/{0}");
  }

  @Test
  public void testValidateDisplayUrlPatternPath() throws DfException {
    testValidateDisplayUrlPattern("http://webtopurl/drl{1}");
  }

  @Test(expected = InvalidConfigurationException.class)
  public void testValidateDisplayUrlPatternEmptyPattern() throws DfException {
    testValidateDisplayUrlPattern("");
  }

  @Test(expected = InvalidConfigurationException.class)
  public void testValidateDisplayUrlPatternBadPattern() throws DfException {
    testValidateDisplayUrlPattern("{0}tp://webtop/");
  }

  @Test(expected = InvalidConfigurationException.class)
  public void testValidateDisplayUrlPatternNoSubstitutions()
      throws DfException {
    testValidateDisplayUrlPattern("http://webtop/");
  }

  private void testDateToString(String version, String expected)
      throws DfException {
    InitTestProxies initProxies = new InitTestProxies();
    initProxies.setServerVersion(version);
    DocumentumAdaptor adaptor =
        new DocumentumAdaptor(initProxies.getProxyClientX());
    initializeAdaptor(adaptor, "/Folder1/path1", ";");
    assertEquals(expected, adaptor.dateToStringFunction);
  }

  @Test
  public void testDateToString_version6() throws DfException {
    testDateToString("6.5.0.033  Win32.SQLServer", "DATETOSTRING");
  }

  @Test
  public void testDateToString_version7() throws DfException {
    testDateToString("7.2.0000.0155  Win64.SQLServer", "DATETOSTRING_LOCAL");
  }

  @Test
  public void testDateToString_version75() throws DfException {
    testDateToString("7.5.0000.0100  Win32.SQLServer", "DATETOSTRING_LOCAL");
  }

  @Test
  public void testDateToString_version8() throws DfException {
    testDateToString("8.0.0000.0000  Win64.SQLServer", "DATETOSTRING_LOCAL");
  }

  @Test
  public void testDateToString_version10() throws DfException {
    testDateToString("10.0.0000.0010  Win64.SQLServer", "DATETOSTRING_LOCAL");
  }

  /* Mock proxy classes backed by the H2 database tables. */
  private class H2BackedTestProxies {

    public IDfClientX getProxyClientX() {
      return Proxies.newProxyInstance(IDfClientX.class, new ClientXMock());
    }

    private class ClientXMock {
      public String getDFCVersion() {
        return "1.0.0.000 (Mock DFC)";
      }

      public IDfClient getLocalClient() {
        return Proxies.newProxyInstance(IDfClient.class, new ClientMock());
      }

      public IDfLoginInfo getLoginInfo() {
        return Proxies.newProxyInstance(IDfLoginInfo.class,
            new LoginInfoMock());
      }

      public IDfQuery getQuery() {
        return Proxies.newProxyInstance(IDfQuery.class, newQuery());
      }
    }

    private class ClientMock {
      public IDfSessionManager newSessionManager() {
        return Proxies.newProxyInstance(IDfSessionManager.class,
            new SessionManagerMock());
      }
    }

    private class LoginInfoMock {
      public void setPassword(String password) {
      }

      public void setUser(String username) {
      }
    }

    /** Factory method for creating a new Query. */
    public Object newQuery() {
      return new QueryMock();
    }

    protected class QueryMock {
      protected String query;

      public void setDQL(String query) {
        this.query = query;
      }

      public IDfCollection execute(IDfSession session, int arg1)
          throws DfException {
        return Proxies.newProxyInstance(IDfCollection.class,
            new CollectionMock(query));
      }
    }

    protected class CollectionMock {
      final Statement stmt;
      protected final ResultSet rs;

      public CollectionMock(String query) throws DfException {
        try {
          stmt = getConnection().createStatement();
          // The test dm_group table is ROW_BASED in implementation.
          // If not fetching ROW_BASED, then force DISTINCT on the SELECT.
          if (query.contains(" FROM dm_group ")
              && !query.contains("ENABLE(ROW_BASED)")) {
            query = query.replaceFirst("^SELECT ", "SELECT DISTINCT ");
          }
          query = query.replaceAll("DATETOSTRING(_LOCAL)?", "FORMATDATETIME")
              .replace("DATE(", "PARSEDATETIME(")
              .replace("yyyy-mm-dd hh:mi:ss", "yyyy-MM-dd HH:mm:ss")
              .replaceAll("TYPE\\((dm_document_subtype|dm_sysobject_subtype|"
                  + "dm_document|dm_folder)\\)", "r_object_type LIKE '$1%'")
              .replace("FOLDER(", "(mock_object_path LIKE ")
              .replace("',descend", "%'")
              .replace("ENABLE(ROW_BASED)", "")
              .replace("ENABLE(RETURN_TOP", "LIMIT (");
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
      public IDfSession newSession(String docbaseName) {
        return Proxies.newProxyInstance(IDfSession.class, new SessionMock());
      }

      public IDfSession getSession(String docbaseName) {
        return newSession(docbaseName);
      }

      public void release(IDfSession session) {
      }

      public void setIdentity(String docbaseName, IDfLoginInfo loginInfo) {
      }
    }

    private class SessionMock {
      public String getServerVersion() {
        return "1.0.0.000 (Mock CS)";
      }

      public IDfACL getObject(IDfId id) throws DfException {
        String query = String.format(
            "SELECT r_object_id FROM dm_acl WHERE r_object_id = '%s'",
            id.toString());
        try (Connection connection = getConnection();
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(query)) {
          if (rs.first()) {
            return Proxies.newProxyInstance(IDfACL.class,
                new AclMock(id.toString()));
          } else {
            throw new DfIdNotFoundException(id);
          }
        } catch (SQLException e) {
          throw new DfException(e);
        }
      }

      public IDfSysObject getObjectByPath(String path) throws DfException {
        String query = String.format(
            "SELECT *, mock_object_path AS r_folder_path "
            + "FROM dm_sysobject WHERE mock_object_path = '%s'", path);
        try (Connection connection = getConnection();
             Statement stmt = connection.createStatement();
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

      public Object getObjectByQualification(String query) throws DfException {
        if (Strings.isNullOrEmpty(query)) {
          return null;
        }
        try (Connection connection = getConnection();
             Statement stmt = connection.createStatement();
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

      public IDfEnumeration getObjectPaths(IDfId id) throws DfException {
        String query = String.format("SELECT i_folder_id FROM dm_sysobject "
            + "WHERE r_object_id = '%s'", id.toString());

        try (Connection connection = getConnection();
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(query)) {
          if (rs.next()) {
            return Proxies.newProxyInstance(IDfEnumeration.class,
                new EnumerationMock(rs.getString("i_folder_id")));
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
            "SELECT s.*, f.r_folder_path FROM dm_sysobject s "
            + "JOIN dm_folder f ON s.r_object_id = f.r_object_id "
            + "WHERE s.r_object_id = '%s'", spec);
        try (Connection connection = getConnection();
             Statement stmt = connection.createStatement();
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

    private class SysObjectMock {
      private final String id;
      private final String name;
      private final String type;
      private final long contentSize;
      private final int pageCount;
      private final String mimeType;
      private final String content;
      private final String aclId;
      private final Date lastModified;
      private final boolean isVirtualDocument;
      private final Multimap<String, String> attributes;

      public SysObjectMock(ResultSet rs) throws SQLException {
        id = rs.getString("r_object_id");
        name = rs.getString("object_name");
        type = rs.getString("r_object_type");
        contentSize = rs.getLong("r_content_size");
        pageCount = rs.wasNull() ? 0 : 1;
        mimeType = rs.getString("mock_mime_type");
        content = rs.getString("mock_content");
        aclId = rs.getString("mock_acl_id");
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

      public int getPageCount() {
        return pageCount;
      }

      public long getContentSize() {
        return contentSize;
      }

      public InputStream getContent() throws DfException {
        if (pageCount == 0) {
          throw new DfException("Invalid page number");
        } else {
          return new ByteArrayInputStream(content.getBytes(UTF_8));
        }
      }

      public IDfType getType() {
        return Proxies.newProxyInstance(IDfType.class, new TypeMock(type));
      }

      public IDfFormat getFormat() {
        return Proxies.newProxyInstance(IDfFormat.class,
            new FormatMock(mimeType));
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

      public IDfACL getACL() {
        return Proxies.newProxyInstance(IDfACL.class,
            new AclMock(aclId.toString()));
      }
    }

    private class FormatMock {
      private final String mimeType;

      public FormatMock(String mimeType) {
        this.mimeType = mimeType;
      }

      public String getMIMEType() {
        return mimeType;
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
        try (Connection connection = getConnection();
             Statement stmt = connection.createStatement();
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
        IDfSessionManager sessionManager =
            getProxyClientX().getLocalClient().newSessionManager();
        IDfSession session = sessionManager.getSession("foo");
        try {
          return (IDfSysObject) session.getObjectByPath(childPath);
        } finally {
          sessionManager.release(session);
        }
      }
    }

    private class FolderMock extends SysObjectMock {
      private String[] folderPaths;

      public FolderMock(ResultSet rs) throws SQLException {
        super(rs);
        this.folderPaths = rs.getString("r_folder_path").split(",");
      }
       
      public int getFolderPathCount() {
        return folderPaths.length;
      }

      public String getFolderPath(int index) {
        return folderPaths[index];
      }

      public IDfCollection getContents(String colNames) throws DfException {
        String query = String.format(
            "SELECT %s FROM dm_sysobject WHERE i_folder_id = '%s'",
            colNames, getObjectId());
        return Proxies.newProxyInstance(IDfCollection.class,
            new CollectionMock(query));
      }
    }

    private class TypeMock {
      private final String type;
      private final ImmutableMap<String, String> superTypes =
          ImmutableMap.<String, String>builder()
          .put("dm_document_subtype", "dm_document")
          .put("dm_document_virtual", "dm_sysobject")
          .put("dm_document", "dm_sysobject")
          .put("dm_sysobject_subtype", "dm_sysobject")
          .put("dm_folder_subtype", "dm_folder")
          .put("dm_folder", "dm_sysobject")
          .build();

      public TypeMock(String type) {
        this.type = type;
      }

      public boolean isTypeOf(String otherType) {
        if (type.startsWith(otherType)) {
          return true;
        }

        String parent = superTypes.get(type);
        while (!Strings.isNullOrEmpty(parent)) {
          if (parent.startsWith(otherType)) {
            return true;
          }
          parent = superTypes.get(parent);
        }
        return false;
      }

      public String getName() {
        return type;
      }

      public IDfType getSuperType() {
        if (superTypes.containsKey(type)) {
          return Proxies.newProxyInstance(IDfType.class,
              new TypeMock(superTypes.get(type)));
        } else {
          return null;
        }
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

      @Override
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
        try (Connection connection = getConnection();
             Statement stmt = connection.createStatement();
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

      public IDfId getObjectId() {
        return Proxies.newProxyInstance(IDfId.class, new IdMock(id));
      }
    }

    public class EnumerationMock {
      private final UnmodifiableIterator<String> iter;

      public EnumerationMock(String folderIds) {
        iter = Iterators.forArray(folderIds.split("\\s*,\\s*"));
      }

      public boolean hasMoreElements() throws DfException {
        return iter.hasNext();
      }

      public IDfObjectPath nextElement() throws DfException {
        return Proxies.newProxyInstance(IDfObjectPath.class,
            new ObjectPathMock(iter.next()));
      }
    }

    public class ObjectPathMock {
      private final String id;

      public ObjectPathMock(String id) throws DfException {
        this.id = id;
      }

      public String getFullPath() throws DfException {
        //TODO(sveldurthi): Add test for multiple r_folder_path values.
        String query =
            String.format("SELECT r_folder_path "
                + "FROM dm_folder WHERE r_object_id = '%s'", id);
        try (Connection connection = getConnection();
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(query)) {
          if (rs.next()) {
            return rs.getString("r_folder_path");
          }
          return null;
        } catch (SQLException e) {
          throw new DfException(e);
        }
      }
    }
  }

  /** Mock proxy implementations that throw Exceptions when iterating over
      a result set. */
  private class ExceptionalResultSetTestProxies extends H2BackedTestProxies {
    private final String queryFragment;
    private final Iterator<Integer> failIterations;
    private final DfException exceptionToThrow;

    ExceptionalResultSetTestProxies(String queryFragment,
        Iterator<Integer> failIterations, DfException exceptionToThrow) {
      this.queryFragment = queryFragment;
      this.failIterations = failIterations;
      this.exceptionToThrow = exceptionToThrow;
    }

    @Override
    public Object newQuery() {
      return new ExceptionalQueryMock();
    }

    private class ExceptionalQueryMock extends QueryMock {
      @Override
      public IDfCollection execute(IDfSession session, int queryType)
          throws DfException {
        return Proxies.newProxyInstance(IDfCollection.class,
            (query.contains(queryFragment))
            ? new ExceptionalCollectionMock(query, failIterations.next())
            : new CollectionMock(query));
      }
    }

    private class ExceptionalCollectionMock extends CollectionMock {
      private final int failIteration;
      private int iteration;

      public ExceptionalCollectionMock(String query, int failIteration)
          throws DfException {
        super(query);
        this.failIteration = failIteration;
        iteration = 0;
      }

      @Override
      public boolean next() throws DfException {
        if (iteration++ == failIteration) {
          throw exceptionToThrow;
        } else {
          return super.next();
        }
      }
    }
  }

  private DocumentumAdaptor getObjectUnderTest() throws DfException {
    return getObjectUnderTest(ImmutableMap.<String, String>of());
  }

  private DocumentumAdaptor getObjectUnderTest(Map<String, ?> configMap)
      throws DfException {
    return getObjectUnderTest(new H2BackedTestProxies(), configMap);
  }

  private DocumentumAdaptor getObjectUnderTest(H2BackedTestProxies proxyCls,
      Map<String, ?> configMap) throws DfException {
    IDfClientX dmClientX = proxyCls.getProxyClientX();
    DocumentumAdaptor adaptor = new DocumentumAdaptor(dmClientX);

    AdaptorContext context = ProxyAdaptorContext.getInstance();
    Config config = initTestAdaptorConfig(context);
    for (Map.Entry<String, ?> entry : configMap.entrySet()) {
      config.overrideKey(entry.getKey(), entry.getValue().toString());
    }
    adaptor.init(context);
    return adaptor;
  }

  private void insertCabinets(String... cabinets) throws SQLException {
    for (String cabinet : cabinets) {
      // The extra row with a null r_folder_path simulates a row-based query
      // result. Our fake getValueCount correctly returns 0 for that row.
      executeUpdate(String.format("INSERT INTO dm_cabinet "
          + "(r_object_id, r_folder_path, object_name, owner_name) "
          + "VALUES('%1$s',null,'%3$s','%4$s'),('%1$s','%2$s','%3$s','%4$s')",
          "0c" + cabinet, "/" + cabinet, cabinet, cabinet));
    }
  }

  private void checkGetRootContent(String whereClause, int maxHtmlLinks,
      String... expectedCabinets) throws Exception {
    List<String> queries = new ArrayList<>();
    Logging.captureLogMessages(DocumentumAdaptor.class,
        "Get All Cabinets Query", queries);

    String startPath = "/";
    MockResponse response = getDocContent(
        ImmutableMap.of(
            "documentum.src", startPath,
            "documentum.maxHtmlSize", maxHtmlLinks,
            "documentum.cabinetWhereCondition", whereClause),
        new MockRequest(DocumentumAdaptor.docIdFromPath(startPath)));

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

    DocIdEncoder docidEncoder =
        ProxyAdaptorContext.getInstance().getDocIdEncoder();
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

  /** @see #testGetDocIdsRootStartPathNoCabinets() */
  @Test
  public void testGetRootContentNoCabinets() throws Exception {
    checkGetRootContent("1=1", 100);
  }

  /** @see #testGetDocIdsRootStartPathEmptyWhereClause()  */
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

  /** @see #testGetDocIdsRootStartPathAddedWhereClause()  */
  @Test
  public void testGetRootContentAddedWhereClause() throws Exception {
    insertCabinets("System", "Temp", "Cabinet1", "Cabinet2");
    checkGetRootContent("object_name NOT IN ('System', 'Temp')",
        100, "Cabinet1", "Cabinet2");
  }

  /** @see #testGetDocIdsRootStartPathDefaultWhereClause() */
  @Test
  public void testGetRootContentDefaultWhereClause() throws Exception {
    executeUpdate(
        "CREATE TABLE dm_docbase_config (owner_name varchar)",
        "INSERT INTO dm_docbase_config (owner_name) VALUES('Owner')",
        "CREATE TABLE dm_server_config (r_install_owner varchar)",
        "INSERT INTO dm_server_config (r_install_owner) VALUES('Installer')");
    insertCabinets("Integration", "Resources", "System", "Temp");
    insertCabinets("Templates", "Owner", "Installer", "dm_bof_registry");
    insertCabinets("Cabinet1", "Cabinet2");

    Config config = ProxyAdaptorContext.getInstance().getConfig();
    new DocumentumAdaptor(null).initConfig(config);

    checkGetRootContent(config.getValue("documentum.cabinetWhereCondition"),
        100, "Cabinet1", "Cabinet2");
  }

  /** @see #testGetDocIdsRootStartPathInvalidWhereClause() */
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

  private void insertDocument(String path) throws SQLException {
    insertDocument(new Date(), path, "text/plain", "Hello World");
  }

  private void insertDocument(Date lastModified, String path,
       String mimeType, String content) throws SQLException {
    String name = path.substring(path.lastIndexOf("/") + 1);
    executeUpdate(String.format(
        "insert into dm_sysobject(r_object_id, object_name, mock_object_path, "
        + "r_object_type, mock_mime_type, mock_content, r_modify_date, "
        + "mock_acl_id, r_content_size) "
        + "values('%s', '%s', '%s', '%s', '%s', '%s', {ts '%s'}, '%s', %d)",
        "09" + name, name, path, "dm_document", mimeType, content,
        dateFormat.format(lastModified), DEFAULT_ACL,
        (content == null) ? null : content.length()));
  }

  private void insertDocument(String lastModified, String id, String path,
      String... folderIds) throws SQLException {
    String name = path.substring(path.lastIndexOf("/") + 1);
    insertSysObject(lastModified, id, name, path, "dm_document", folderIds);
  }

  private void setDocumentSize(String id, long size) throws SQLException {
    executeUpdate(String.format(
        "UPDATE dm_sysobject SET r_content_size = %d "
        + "WHERE r_object_id = '%s'", size, id));
  }

  private void insertFolder(String lastModified, String id, String... paths)
       throws SQLException {
    executeUpdate(String.format(
        "insert into dm_folder(r_object_id, r_folder_path) values('%s', '%s')",
        id, Joiner.on(",").join(paths)));
    for (String path : paths) {
      String name = path.substring(path.lastIndexOf("/") + 1);
      insertSysObject(lastModified, id, name, path, "dm_folder");
    }
  }

  private void setParentFolderId(String id, String parentId)
      throws SQLException {
    executeUpdate(String.format(
        "UPDATE dm_sysobject SET i_folder_id = '%s' WHERE r_object_id = "
            + "'%s'", parentId, id));
  }

  private void insertSysObject(String lastModified, String id, String name,
      String path, String type, String... folderIds) throws SQLException {
    executeUpdate(String.format(
        "insert into dm_sysobject(r_object_id, object_name, mock_object_path, "
        + "r_object_type, i_folder_id, r_modify_date, mock_acl_id) "
        + "values('%s', '%s', '%s', '%s', '%s', {ts '%s'}, '%s')",
        id, name, path, type, Joiner.on(",").join(folderIds), lastModified,
        DEFAULT_ACL));
  }

  private void setSysObjectACL(String path, String aclId)
      throws SQLException {
    executeUpdate(String.format(
        "UPDATE dm_sysobject SET mock_acl_id = '%s' WHERE mock_object_path = "
        + "'%s'", aclId, path));
  }

  private void testDocContent(Date lastCrawled, Date lastModified,
      boolean expectNoContent) throws DfException, IOException, SQLException {
    String path = START_PATH + "/object1";
    String mimeType = "text/html";
    String content = "<html><body>Hello</body></html>";
    insertDocument(lastModified, path, mimeType, content);

    MockResponse response = getDocContent(ImmutableMap.<String, String>of(),
        new MockRequest(DocumentumAdaptor.docIdFromPath(path), lastCrawled));

    // Our mocks, like Documentum, only store seconds, not milliseconds.
    assertEquals(new Date((lastModified.getTime() / 1000) * 1000),
        response.lastModified);
    assertFalse(response.notModified);
    assertFalse(response.metadata.isEmpty());
    assertNotNull(response.acl);
    if (expectNoContent) {
      assertTrue(response.noContent);
      assertEquals(null, response.contentType);
      assertEquals(null, response.content);
    } else {
      assertFalse(response.noContent);
      assertEquals(mimeType, response.contentType);
      assertEquals(content, response.content.toString(UTF_8.name()));
    }
  }

  private MockResponse getDocContent(String path)
      throws DfException, IOException {
    Request request = new MockRequest(DocumentumAdaptor.docIdFromPath(path));
    return getDocContent(ImmutableMap.<String, String>of(), request);
  }

  private MockResponse getDocContent(Map<String, ?> configOverrides,
      Request request) throws DfException, IOException {
    DocumentumAdaptor adaptor = getObjectUnderTest(configOverrides);
    MockResponse response = new MockResponse();
    adaptor.getDocContent(request, response);
    return response;
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

  private MockResponse getNoContent(String content, long... size)
      throws Exception {
    String path = START_PATH + "/object1";
    insertDocument(new Date(), path, "text/plain", content);

    // This hack with essentially an optional argument is instead of a
    // hack to treat 0 specially.
    if (size.length > 0) {
      assertEquals(1, size.length);
      setDocumentSize("09object1", size[0]);
    }

    return getDocContent(path);
  }

  @Test
  public void testGetDocContent_noFile() throws Exception {
    MockResponse response = getNoContent(null);
    assertEquals(null, response.contentType);
    assertEquals("", response.content.toString(UTF_8.name()));
  }

  @Test
  public void testGetDocContent_emptyFile() throws Exception {
    MockResponse response = getNoContent("");
    assertEquals(null, response.contentType);
    assertEquals("", response.content.toString(UTF_8.name()));
  }

  @Test
  public void testGetDocContent_largeFile() throws Exception {
    MockResponse response =
        getNoContent("hello, world", Integer.MAX_VALUE + 1L);
    assertEquals("text/plain", response.contentType);
    assertEquals("hello, world", response.content.toString(UTF_8.name()));
  }

  @Test
  public void testGetDocContent_hugeFile() throws Exception {
    MockResponse response =
        getNoContent("Call me Ishmael....", Integer.MAX_VALUE + 2L);
    assertEquals(null, response.contentType);
    assertEquals("", response.content.toString(UTF_8.name()));
  }

  private String getDisplayUrl(String displayUrlPattern, String path)
      throws Exception {
    assertTrue(path, path.startsWith(START_PATH));
    insertDocument(path);

    MockResponse response = getDocContent(
        ImmutableMap.of("documentum.displayUrlPattern", displayUrlPattern),
        new MockRequest(DocumentumAdaptor.docIdFromPath(path)));

    assertNotNull(response.toString(), response.displayUrl);
    return response.displayUrl.toString();
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

  private Acl getACL(String path, MarkAllDocsPublic markAllDocsPublic)
      throws Exception {
    assertTrue(path, path.startsWith(START_PATH));

    MockResponse response = getDocContent(
        ImmutableMap.of("adaptor.markAllDocsAsPublic", markAllDocsPublic),
        new MockRequest(DocumentumAdaptor.docIdFromPath(path)));

    return response.acl;
  }

  @Test
  public void testDocumentACL() throws Exception {
    String path = "/Folder1/path1/object1";
    String documentACL = "45DocumentACL";
    insertDocument(path);
    setSysObjectACL(path, documentACL);

    Acl acl = getACL(path, MarkAllDocsPublic.FALSE);
    assertNotNull(acl);
    assertEquals(new DocId(documentACL), acl.getInheritFrom());
  }

  @Test
  public void testFolderACL() throws Exception {
    String now = getNowPlusMinutes(0);
    String folderId = "0b01081f80078d29";
    String folder = START_PATH + "/path2";
    String folderACL = "45FolderAcl";
    insertFolder(now, folderId, folder);
    setSysObjectACL(folder, folderACL);

    Acl acl = getACL(folder, MarkAllDocsPublic.FALSE);
    assertNotNull(acl);
    assertEquals(new DocId(folderACL), acl.getInheritFrom());
  }

  @Test
  public void testDocumentAclMarkAllDocsPublic() throws Exception {
    String path = "/Folder1/path1/object1";
    String documentACL = "45DocumentACL";
    insertDocument(path);
    setSysObjectACL(path, documentACL);

    Acl acl = getACL(path, MarkAllDocsPublic.TRUE);
    assertNull(acl);
  }

  @Test
  public void testFolderAclMarkAllDocsPublic() throws Exception {
    String now = getNowPlusMinutes(0);
    String folderId = "0b01081f80078d29";
    String folder = START_PATH + "/path2";
    String folderACL = "45FolderAcl";
    insertFolder(now, folderId, folder);
    setSysObjectACL(folder, folderACL);

    Acl acl = getACL(folder, MarkAllDocsPublic.TRUE);
    assertNull(acl);
  }

  private void testFolderAcl(boolean indexFolder, boolean allDocsPubilc,
      boolean expectAcl) throws Exception {
    String now = getNowPlusMinutes(0);
    String folderId = "0bfolder1";
    String folder = START_PATH + "/path2";
    String folderACL = "45FolderAcl";
    insertFolder(now, folderId, folder);
    setSysObjectACL(folder, folderACL);

    MockResponse response = getDocContent(ImmutableMap.of(
            "adaptor.markAllDocsAsPublic", allDocsPubilc,
            "documentum.indexFolders", indexFolder),
            new MockRequest(DocumentumAdaptor.docIdFromPath(folder)));

    if (expectAcl) {
      assertNotNull(response.acl);
      assertEquals(new DocId(folderACL), response.acl.getInheritFrom());
    } else {
      assertNull(response.acl);
    }
  }

  @Test
  public void testFolderAcl_noIndex_public() throws Exception {
    testFolderAcl(false, true, false);
  }

  @Test
  public void testFolderAcl_index_public() throws Exception {
    testFolderAcl(true, true, false);
  }

  @Test
  public void testFolderAcl_noIndex_nonPublic() throws Exception {
    testFolderAcl(false, false, true);
  }

  @Test
  public void testFolderAcl_index_nonPublic() throws Exception {
    testFolderAcl(true, false, true);
  }

  private void testFolderMetadata(TreeMultimap<String, String> attrs,
      Map<String, String> configOverrides,
      TreeMultimap<String, String> expected) throws Exception {
    String now = getNowPlusMinutes(0);
    String folderId = "0bfolder1";
    String folder = START_PATH + "/path2";
    insertFolder(now, folderId, folder);
    writeAttributes(folderId, attrs);

    Request request = new MockRequest(DocumentumAdaptor.docIdFromPath(folder));
    MockResponse response = getDocContent(configOverrides, request);

    assertEquals(expected, response.metadata);
  }

  @Test
  public void testFolderMetadata_default() throws Exception {
    TreeMultimap<String, String> attributes = TreeMultimap.create();
    attributes.put("attr1", "value1");
    attributes.put("attr2", "value2");
    attributes.put("attr3", "value3");
    TreeMultimap<String, String> expected = TreeMultimap.create(attributes);
    expected.put("r_object_id", "0bfolder1");

    // documentum.indexFolders is set to true by default.
    testFolderMetadata(attributes, ImmutableMap.<String, String>of(), expected);
  }

  @Test
  public void testFolderMetadata_noIndex() throws Exception {
    TreeMultimap<String, String> attributes = TreeMultimap.create();
    attributes.put("attr1", "value1");
    attributes.put("attr2", "value2");
    attributes.put("attr3", "value3");
    TreeMultimap<String, String> expected = TreeMultimap.create(attributes);
    expected.put("r_object_id", "0bfolder1");

    testFolderMetadata(attributes,
        ImmutableMap.of("documentum.indexFolders", "false"), expected);
  }

  @Test
  public void testNoIndex_rootFolder() throws Exception {
    insertCabinets("System", "Cabinet1", "Cabinet2");
    MockResponse response =
        getDocContent(ImmutableMap.of("documentum.src", "/"),
            new MockRequest(DocumentumAdaptor.docIdFromPath("/")));

    assertTrue(response.noIndex);
  }

  private void testNoIndex(Map<String, ?> configOverrides, boolean expected)
      throws Exception {
    String now = getNowPlusMinutes(0);
    String folderId = "0bfolder1";
    String folder = START_PATH + "/path2";
    String folderACL = "45FolderAcl";
    insertFolder(now, folderId, folder);
    setSysObjectACL(folder, folderACL);

    MockResponse response =
        getDocContent(configOverrides,
            new MockRequest(DocumentumAdaptor.docIdFromPath(folder)));

    assertEquals(expected, response.noIndex);
  }

  @Test
  public void testIndexFolder_default() throws Exception {
    testNoIndex(ImmutableMap.<String, String>of(), false);
  }

  @Test
  public void testIndexFolder_false() throws Exception {
    testNoIndex(ImmutableMap.of("documentum.indexFolders", "false"), true);
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
    executeUpdate(ddl.toString());

    for (String attr : attrs.keySet()) {
      for (String value : attrs.get(attr)) {
        executeUpdate(String.format(
            "INSERT INTO attributes (r_object_id, %s) VALUES ('%s', '%s')",
            attr, objectId, value));
      }
    }
  }

  private Multimap<String, String> readAttributes(String objectId)
      throws SQLException {
    Multimap<String, String> attributes = TreeMultimap.create();
    try (Connection connection = getConnection()) {
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

  private void testExcludeMetadata(TreeMultimap<String, String> attrs,
      String excludedAttrs, TreeMultimap<String, String> expected)
      throws Exception {
    String path = START_PATH + "/object1";
    String objectId = "09object1";
    insertDocument(path);
    writeAttributes(objectId, attrs);

    Map<String, String> configOverrides = (excludedAttrs == null)
        ? ImmutableMap.<String, String>of()
        : ImmutableMap.of("documentum.excludedAttributes", excludedAttrs);

    Request request = new MockRequest(DocumentumAdaptor.docIdFromPath(path));
    MockResponse response = getDocContent(configOverrides, request);

    assertEquals(expected, response.metadata);
  }

  private void testMetadata(TreeMultimap<String, String> attrs,
      TreeMultimap<String, String> expected) throws Exception {
    testExcludeMetadata(attrs, null, expected);
  }

  @Test
  public void testSingleValueMetadata() throws Exception {
    TreeMultimap<String, String> attributes = TreeMultimap.create();
    attributes.put("attr1", "value1");
    attributes.put("attr2", "value2");
    attributes.put("attr3", "value3");
    TreeMultimap<String, String> expected = TreeMultimap.create(attributes);
    expected.put("r_object_id", "09object1");
    testMetadata(attributes, expected);
  }

  @Test
  public void testMultiValueMetadata() throws Exception {
    TreeMultimap<String, String> attributes = TreeMultimap.create();
    attributes.put("attr1", "value1");
    attributes.put("attr1", "value2");
    attributes.put("attr1", "value3");
    assertEquals(1, attributes.keySet().size());
    assertEquals(3, attributes.get("attr1").size());
    TreeMultimap<String, String> expected = TreeMultimap.create(attributes);
    expected.put("r_object_id", "09object1");
    testMetadata(attributes, expected);
  }

  @Test
  public void testEmptyValueMetadata() throws Exception {
    TreeMultimap<String, String> attributes = TreeMultimap.create();
    attributes.put("attr1", "value1");
    attributes.put("attr2", "value2");
    attributes.put("attr2", "");
    attributes.put("attr3", "");
    TreeMultimap<String, String> expected = TreeMultimap.create(attributes);
    expected.put("r_object_id", "09object1");
    testMetadata(attributes, expected);
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
    String excluded = "foo, bar, r_object_id";
    expected.removeAll("foo");
    expected.removeAll("bar");
    testExcludeMetadata(attributes, excluded, expected);
  }

  @Test
  public void testObjectTypeMetadata() throws Exception {
    TreeMultimap<String, String> attributes = TreeMultimap.create();
    attributes.put("r_object_type", "dm_document");
    attributes.put("attr2", "value2");
    TreeMultimap<String, String> expected = TreeMultimap.create(attributes);
    expected.put("r_object_id", "09object1");
    expected.removeAll("r_object_type");
    expected.put("r_object_type", "dm_document");
    expected.put("r_object_type", "dm_sysobject");
    testMetadata(attributes, expected);
  }

  private void insertVirtualDocument(String vdocPath, String mimeType,
      String content, String... children) throws SQLException {
    String name = vdocPath.substring(vdocPath.lastIndexOf("/") + 1);
    String vdocId = "09" + name;
    String now = getNowPlusMinutes(0);
    executeUpdate(String.format(
        "INSERT INTO dm_sysobject(r_object_id, object_name, mock_object_path, "
        + "r_object_type, r_is_virtual_doc, mock_mime_type, mock_content, "
        + "r_modify_date, mock_acl_id, r_content_size) VALUES("
        + "'%s', '%s', '%s', '%s', TRUE, '%s', '%s', {ts '%s'}, '%s', %d)",
        vdocId, name, vdocPath, "dm_document_virtual", mimeType, content,
        now, DEFAULT_ACL, (content == null) ? null : content.length()));
    for (String child : children) {
      insertDocument(now, "09" + child, vdocPath + "/" + child, vdocId);
    }
  }

  @Test
  public void testVirtualDocContentNoChildren() throws Exception {
    String path = START_PATH + "/vdoc";
    String objectMimeType = "text/html";
    String objectContent = "<html><body>Hello</body></html>";
    insertVirtualDocument(path, objectMimeType, objectContent);

    MockResponse response = getDocContent(path);

    assertEquals(objectMimeType, response.contentType);
    assertEquals(objectContent, response.content.toString(UTF_8.name()));
    assertTrue(response.anchors.isEmpty());
  }

  @Test
  public void testVirtualDocContentWithChildren() throws Exception {
    String path = START_PATH + "/vdoc";
    String objectMimeType = "text/html";
    String objectContent = "<html><body>Hello</body></html>";
    insertVirtualDocument(path, objectMimeType, objectContent,
        "object1", "object2", "object3");

    MockResponse response = getDocContent(path);

    assertEquals(objectMimeType, response.contentType);
    assertEquals(objectContent, response.content.toString(UTF_8.name()));

    // Verify child links.
    assertEquals(3, response.anchors.size());
    for (String name : ImmutableList.of("object1", "object2", "object3")) {
      URI uri = response.anchors.get(name);
      assertNotNull(uri);
      assertTrue(uri.toString().endsWith(path + "/" + name + ":09" + name));
    }
  }

  @Test
  public void testFolderDocContent() throws Exception {
    String now = getNowPlusMinutes(0);
    String folderId = "0b01081f80078d29";
    String folder = START_PATH + "/path2";
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

    MockResponse response = getDocContent(folder);

    assertFalse(response.notFound);
    assertEquals("text/html; charset=UTF-8", response.contentType);
    assertEquals(expected.toString(), response.content.toString(UTF_8.name()));
  }

  @Test
  public void testFolderDocContent_CustomType() throws Exception {
    String folderId = "0b001";
    String folder = "/Folder1/path1/path";
    insertFolder(JAN_1970, folderId, folder);
    insertDocument(JAN_1970, "09001", folder + "/file1", folderId);
    StringBuilder expected =
        new StringBuilder()
            .append("<!DOCTYPE html>\n")
            .append("<html><head><title>Folder path</title></head><body>")
            .append("<h1>Folder path</h1>")
            .append("<li><a href=\"path/file1\">file1</a></li>")
            .append("</body></html>");

    MockResponse response =
        getDocContent(ImmutableMap.<String, String>of(
            "documentum.documentTypes", "dm_sysobject"),
            new MockRequest(DocumentumAdaptor.docIdFromPath(folder)));

    assertEquals(expected.toString(), response.content.toString(UTF_8.name()));
  }

  @Test
  public void testFolderLastModified() throws Exception {
    String now = getNowPlusMinutes(0);
    String folderId = "0b01081f80078d29";
    String folder = START_PATH + "/path2";
    insertFolder(now, folderId, folder);
    MockResponse response = getDocContent(folder);

    assertEquals(dateFormat.parse(now), response.lastModified);
  }

  @Test
  public void testFolderDisplayUrl() throws Exception {
    String now = getNowPlusMinutes(0);
    String folderId = "0b01081f80078d29";
    String folder = START_PATH + "/path2";
    insertFolder(now, folderId, folder);
    MockResponse response = getDocContent(folder);

    assertNotNull(response.displayUrl);
    assertEquals("http://webtop/drl/0b01081f80078d29",
        response.displayUrl.toString());
  }

  @Test
  public void testGetDocContentNotFound() throws Exception {
    String path = START_PATH + "/doesNotExist";
    assertTrue(getDocContent(path).notFound);
  }

  @Test
  public void testGetDocContentNotUnderStartPath() throws Exception {
    String now = getNowPlusMinutes(0);
    String path = "/Folder2/path2";
    insertFolder(now, "0b01081f80078d30", path);

    assertFalse(path.startsWith(START_PATH));
    assertTrue(getDocContent(path).notFound);
  }

  /**
   * Builds a list of expected DocId Records that the Pusher should receive.
   */
  private List<Record> expectedRecordsFor(String... paths) {
    ImmutableList.Builder<Record> builder = ImmutableList.builder();
    for (String path : paths) {
      DocId docid = DocumentumAdaptor.docIdFromPath(path);
      builder.add(new Record.Builder(docid).build());
    }
    return builder.build();
  }

  private void testGetDocIds(List<String> startPaths,
      List<Record> expectedRecords)
      throws DfException, IOException, InterruptedException {
    testGetDocIds(
        ImmutableMap.of("documentum.src", Joiner.on(",").join(startPaths)),
        expectedRecords);
  }

  private void testGetDocIds(Map<String, ?> configMap,
      List<Record> expectedRecords)
      throws DfException, IOException, InterruptedException {
    DocumentumAdaptor adaptor = getObjectUnderTest(configMap);
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    adaptor.getDocIds(pusher);

    assertEquals(expectedRecords, pusher.getRecords());
  }

  @Test
  public void testGetDocIdsRootStartPath() throws Exception {
    insertCabinets("Cabinet1", "Cabinet2", "Cabinet3");
    testGetDocIds(startPaths("/"),
        expectedRecordsFor("/Cabinet1", "/Cabinet2", "/Cabinet3"));
  }

  /** @see #testGetRootContentNoCabinets() */
  @Test
  public void testGetDocIdsRootStartPathNoCabinets() throws Exception {
    testGetDocIds(
        ImmutableMap.of(
            "documentum.src", "/",
            "documentum.cabinetWhereCondition", "1=1"),
        expectedRecordsFor());
  }

  /** @see #testGetRootContentEmptyWhereClause() */
  @Test
  public void testGetDocIdsRootStartPathEmptyWhereClause() throws Exception {
    insertCabinets("System", "Temp", "Cabinet1", "Cabinet2");
    testGetDocIds(
        ImmutableMap.of(
            "documentum.src", "/",
            "documentum.cabinetWhereCondition", ""),
        expectedRecordsFor("/System", "/Temp", "/Cabinet1", "/Cabinet2"));
  }

  /** @see #testGetRootContentAddedWhereClause() */
  @Test
  public void testGetDocIdsRootStartPathAddedWhereClause() throws Exception {
    insertCabinets("System", "Temp", "Cabinet1", "Cabinet2");
    testGetDocIds(
        ImmutableMap.of(
            "documentum.src", "/",
            "documentum.cabinetWhereCondition",
                "object_name NOT IN ('System', 'Temp')"),
        expectedRecordsFor("/Cabinet1", "/Cabinet2"));
  }

  /** @see #testGetRootContentDefaultWhereClause() */
  @Test
  public void testGetDocIdsRootStartPathDefaultWhereClause() throws Exception {
    executeUpdate(
        "CREATE TABLE dm_docbase_config (owner_name varchar)",
        "INSERT INTO dm_docbase_config (owner_name) VALUES('Owner')",
        "CREATE TABLE dm_server_config (r_install_owner varchar)",
        "INSERT INTO dm_server_config (r_install_owner) VALUES('Installer')");
    insertCabinets("Integration", "Resources", "System", "Temp");
    insertCabinets("Templates", "Owner", "Installer", "dm_bof_registry");
    insertCabinets("Cabinet1", "Cabinet2", "Cabinet3");

    Config config = ProxyAdaptorContext.getInstance().getConfig();
    new DocumentumAdaptor(null).initConfig(config);

    testGetDocIds(
        ImmutableMap.of(
            "documentum.src", "/",
            "documentum.cabinetWhereCondition",
                config.getValue("documentum.cabinetWhereCondition")),
        expectedRecordsFor("/Cabinet1", "/Cabinet2", "/Cabinet3"));
  }

  /** @see #testGetRootContentInvalidWhereClause() */
  @Test
  public void testGetDocIdsRootStartPathInvalidWhereClause() throws Exception {
    insertCabinets("Cabinet1", "Cabinet2");
    try {
      testGetDocIds(
          ImmutableMap.of(
              "documentum.src", "/",
              "documentum.cabinetWhereCondition", "( xyzzy"),
          expectedRecordsFor());
      fail("Expected exception not thrown.");
    } catch (IOException expected) {
      assertTrue(expected.getCause() instanceof DfException);
    }
  }

  @Test
  public void testGetDocIdsSingleStartPath() throws Exception {
    testGetDocIds(startPaths(START_PATH), expectedRecordsFor(START_PATH));
  }

  @Test
  public void testGetDocIdsMultipleStartPaths() throws Exception {
    String now = getNowPlusMinutes(0);
    String path2 = "/Folder2";
    String path3 = "/Folder3";
    insertFolder(now, "0bFolder2", path2);
    insertFolder(now, "0bFolder3", path3);

    testGetDocIds(startPaths(START_PATH, path2, path3),
        expectedRecordsFor(START_PATH, path2, path3));
  }

  @Test
  public void testGetDocIdsMultipleStartPathsSomeOffline() throws Exception {
    String now = getNowPlusMinutes(0);
    String path2 = "/Folder2";
    String path3 = "/Folder3";
    insertFolder(now, "0bFolder3", path3);

    testGetDocIds(startPaths(START_PATH, path2, path3),
        expectedRecordsFor(START_PATH, path3));
  }

  /**
   * A traversal action includes an expected input checkpoint, an
   * exception to throw, and a final checkpoint to return. All fields
   * are optional and may be null.
   */
  private static class Action {
    public final String input;
    public final DfException error;
    public final String output;

    public Action(String input, DfException error, String output) {
      this.input = input;
      this.error = error;
      this.output = output;
    }
  }

  /**
   * Tests the traversers by replaying a sequence of actions. An
   * assertion will fail if the traverser loops more or fewer times
   * than the given number of actions, or if the checkpoints or thrown
   * exceptions do not match.
   */
  private void testTraverserTemplate(Action... actionArray) throws Exception {
    // The actions are removed from the deque as they are performed.
    final ArrayDeque<Action> actions =
        new ArrayDeque<>(Arrays.asList(actionArray));

    DocumentumAdaptor adaptor = getObjectUnderTest();
    DocumentumAdaptor.TraverserTemplate template =
        adaptor.new TraverserTemplate(Checkpoint.full()) {
            @Override protected void createCollection() {}

            @Override
            protected boolean fillCollection(IDfSession dmSession,
                Principals principals, Checkpoint checkpoint)
                throws DfException {
              assertEquals(actions.getFirst().input, checkpoint.getObjectId());
              if (actions.getFirst().error != null) {
                throw actions.getFirst().error;
              }
              return actions.getFirst().output == null;
            }

            @Override
            protected Checkpoint pushCollection(DocIdPusher pusher) {
              return new Checkpoint(actions.removeFirst().output);
            }
          };
    template.setSleeper(NO_SLEEP);

    // We only expect an exception if the last loop iteration throws.
    ArrayList<DfException> expectedExceptions = new ArrayList<>();
    if (actions.getLast().error != null) {
      expectedExceptions.add(actions.getLast().error);
    }

    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    ArrayList<DfException> savedExceptions = new ArrayList<>();
    template.run(pusher, savedExceptions);
    assertTrue(actions.toString(), actions.isEmpty());
    assertEquals(expectedExceptions, savedExceptions);
  }

  private static final String C = "non-null checkpoint";
  private static final String D = "another checkpoint";
  private static final DfException E = new DfException("first error");
  private static final DfException F = new DfException("second error");

  @Test
  public void testTraverserTemplate_noProgress() throws Exception {
    testTraverserTemplate(
        new Action(null, E, null));
  }

  @Test
  public void testTraverserTemplate_completeTraversal() throws Exception {
    testTraverserTemplate(
        new Action(null, null, null));
  }

  @Test
  public void testTraverserTemplate_impossible() throws Exception {
    // If no exception is thrown, the checkpoint should be null.
    // But if it happens, we expect a second call.
    testTraverserTemplate(
        new Action(null, null, C),
        new Action(C, null, null));
  }

  @Test
  public void testTraverserTemplate_throwThenNoProgress() throws Exception {
    testTraverserTemplate(
        new Action(null, E, C),
        new Action(C, F, C));
  }

  @Test
  public void testTraverserTemplate_throwThenProgress() throws Exception {
    testTraverserTemplate(
        new Action(null, E, C),
        new Action(C, F, D),
        new Action(D, null, null));
  }

  @Test
  public void testTraverserTemplate_throwThenComplete() throws Exception {
    testTraverserTemplate(
        new Action(null, E, C),
        new Action(C, null, null));
  }

  private void insertUsers(String... names) throws SQLException {
    for (String name : names) {
      executeUpdate(String.format("insert into dm_user "
          + "(r_object_id, user_name, user_login_name) "
          + "values('%s', '%s', '%s')",
          "11" + name, name, name));
    }
  }

  private void disableUsers(String... names) throws SQLException {
    // TODO(sveldurthi): modify query to use where user_name in ('u1', 'u2')
    for (String name : names) {
      executeUpdate(String.format(
          "UPDATE dm_user SET user_state = 1 WHERE user_name = '%s'", name));
    }
  }

  private void insertGroup(String groupName, String... members)
      throws SQLException {
    insertGroupEx(getNowPlusMinutes(0), "", groupName, members);
  }

  private void insertLdapGroup(String groupName, String... members)
      throws SQLException {
    insertGroupEx(getNowPlusMinutes(0), "LDAP", groupName, members);
  }

  private void insertGroupEx(String lastModified, String source,
      String groupName, String... members) throws SQLException {
    executeUpdate(String.format("INSERT INTO dm_user"
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
    // Emulate ROW_BASED retrieval by storing the values that way.
    int numRows = Math.max(1, Math.max(users.size(), groups.size()));
    for (int i = 0; i < numRows; i++) {
      executeUpdate(String.format("INSERT INTO dm_group"
          + "(r_object_id, group_name, group_source, r_modify_date, "
          + "users_names, groups_names) VALUES('%s', '%s', '%s', {ts '%s'}, "
          + "%s, %s)",
          "12" + groupName, groupName, source, lastModified,
          (i < users.size()) ? "'" + users.get(i) + "'" : "NULL",
          (i < groups.size()) ? "'" + groups.get(i) + "'" : "NULL"));
    }
  }

  private void createAcl(String id) throws SQLException {
    executeUpdate(String.format(
        "insert into dm_acl(r_object_id) values('%s')", id));
  }

  private boolean isAccessorGroup(String accessorName) throws SQLException {
    try (Connection connection = getConnection();
         Statement stmt = connection.createStatement();
         ResultSet rs = stmt.executeQuery("select r_is_group from dm_user"
             + " where user_name = '" + accessorName + "'")) {
        if (rs.next()) {
          return rs.getBoolean(1);
        }
      }
    return false;
  }

  private void grantPermit(String id, IDfPermit permit) throws SQLException {
    executeUpdate(String.format(
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

  private DocumentumAdaptor getObjectUnderTestNamespaces(
      Map<String, ?> configOverrides) throws DfException {
    return getObjectUnderTestNamespaces(new H2BackedTestProxies(),
      configOverrides);
  }

  private DocumentumAdaptor getObjectUnderTestNamespaces(
      H2BackedTestProxies proxyCls, Map<String, ?> configOverrides)
      throws DfException {
    return getObjectUnderTest(proxyCls,
        ImmutableMap.<String, Object>builder()
        .put("adaptor.namespace", "NS")
        .put("documentum.docbaseName", "Local") // Local Namespace
        .putAll(configOverrides)
        .build());
  }

  private Map<DocId, Acl> getAllAcls() throws Exception {
    return getAllAcls(
        getObjectUnderTestNamespaces(ImmutableMap.<String, String>of()),
        null);
  }

  private Map<DocId, Acl> getAllAcls(String windowsDomain, int batchSize)
      throws DfException, IOException, InterruptedException {
    return getAllAcls(getObjectUnderTestNamespaces(
        ImmutableMap.of(
            "documentum.windowsDomain", windowsDomain,
            "documentum.queryBatchSize", batchSize)),
        null);
  }

  private Map<DocId, Acl> getAllAcls(DocumentumAdaptor adaptor,
      DfException expectedCause)
      throws DfException, IOException, InterruptedException {
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    try {
      adaptor.getDocIds(pusher);
      assertNull("Expected an exception: " + expectedCause, expectedCause);
    } catch (IOException e) {
      if (expectedCause == NO_EXCEPTION || expectedCause != e.getCause()) {
        throw e;
      }
    }
    return pusher.getNamedResources();
  }

  /** Creates ACLs by the supplied object ids and returns a set of DocIds
      for those ACLs. */
  private Set<DocId> createAcls(String... objectIds) throws SQLException {
    ImmutableSet.Builder<DocId> builder = ImmutableSet.builder();
    for (String objectId : objectIds) {
      createAcl(objectId);
      builder.add(new DocId(objectId));
    }
    return builder.build();
  }

  // tests for ACLs
  // TODO: (Srinivas) -  Add a unit test and perform manual test of
  //                     user and group names with quotes in them.
  @Test
  public void testGetAllAcls() throws Exception {
    Set<DocId> expectedDocIds = createAcls("4501081f80000100",
        "4501081f80000101",  "4501081f80000102",  "4501081f80000103",
        "4501081f80000104",  "4501081f80000105",  "4501081f80000106");

    // Fetch all the ACLs in various sized batches.
    // Note: a batch size of 0, means no batching.
    for (int batchSize = 0; batchSize <= expectedDocIds.size() + 1;
         batchSize++) {
      assertEquals("batchSize: " + batchSize,
          expectedDocIds, getAllAcls("", batchSize).keySet());
    }
  }

  private void testGetAclsExceptions(Iterator<Integer> failIterations,
      Map<String, ?> configOverrides,
      DfException expectedCause,
      Set<DocId> expectedDocids)
     throws DfException, IOException, InterruptedException {
    DocumentumAdaptor adaptor = getObjectUnderTestNamespaces(
        new ExceptionalResultSetTestProxies(
            "FROM dm_acl", failIterations,
            (expectedCause != NO_EXCEPTION) ? expectedCause
            : new DfException("Recoverable exception should be handled")),
        configOverrides);
    adaptor.aclTraverser.setSleeper(NO_SLEEP);
    assertEquals(expectedDocids, getAllAcls(adaptor, expectedCause).keySet());
  }

  @Test
  public void testGetAllAclsFirstRowException() throws Exception {
    createAcls("4501081f80000100",
        "4501081f80000101",  "4501081f80000102",  "4501081f80000103",
        "4501081f80000104",  "4501081f80000105",  "4501081f80000106");

    testGetAclsExceptions(Iterators.singletonIterator(0),
        ImmutableMap.<String, String>of(),
        new DfException("Expected exception on first ACL"),
        ImmutableSet.<DocId>of());
  }

  @Test
  public void testGetAllAclsPartialRowException() throws Exception {
    createAcls("4501081f80000100",
        "4501081f80000101",  "4501081f80000102",  "4501081f80000103",
        "4501081f80000104",  "4501081f80000105",  "4501081f80000106");

    testGetAclsExceptions(Iterators.forArray(2, 0),
        ImmutableMap.<String, String>of(),
        new DfException("Expected repeated exception"),
        ImmutableSet.of(new DocId("4501081f80000100"),
            new DocId("4501081f80000101")));
  }

  @Test
  public void testGetAllAclsOtherRowsException() throws Exception {
    Set<DocId> expected = createAcls("4501081f80000100",
        "4501081f80000101",  "4501081f80000102",  "4501081f80000103",
        "4501081f80000104",  "4501081f80000105",  "4501081f80000106");

    // Fetch all the ACLs in various sized batches, failing
    // while iterating over the results in each batch.
    // Note: a batch size of 0, means no batching.
    for (int batchSize = 0; batchSize <= expected.size() + 1; batchSize++) {
      int maxBatchSize = (batchSize == 0) ? expected.size() : batchSize;
      for (int failIter = 1; failIter <= maxBatchSize; failIter++) {
        testGetAclsExceptions(Iterators.cycle(failIter),
            ImmutableMap.of("documentum.queryBatchSize", batchSize),
            NO_EXCEPTION,
            expected);
      }
    }
  }

  @Test
  public void testAllowAcls() throws Exception {
    insertUsers("User1", "User2", "User3", "User4", "User5");
    String id = "4501081f80000100";
    createAcl(id);
    addAllowPermitToAcl(id, "User4", IDfACL.DF_PERMIT_WRITE);
    addAllowPermitToAcl(id, "User5", IDfACL.DF_PERMIT_READ);
    addDenyPermitToAcl(id, "User1", IDfACL.DF_PERMIT_DELETE);
    addDenyPermitToAcl(id, "User2", IDfACL.DF_PERMIT_BROWSE);
    addDenyPermitToAcl(id, "User3", IDfACL.DF_PERMIT_WRITE);

    Map<DocId, Acl> namedResources = getAllAcls();
    Acl acl = namedResources.get(new DocId(id));
    assertEquals(ImmutableSet.of(new UserPrincipal("User4", "NS"),
        new UserPrincipal("User5", "NS")),
        acl.getPermitUsers());
    assertEquals(ImmutableSet.of(new UserPrincipal("User2", "NS")),
        acl.getDenyUsers());
    assertEquals(ImmutableSet.of(), acl.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl.getDenyGroups());
  }

  @Test
  public void testBrowseAcls() throws Exception {
    insertUsers("User1", "User2", "User3", "User4", "User5");
    String id = "4501081f80000100";
    createAcl(id);
    addAllowPermitToAcl(id, "User4", IDfACL.DF_PERMIT_WRITE);
    addAllowPermitToAcl(id, "User5", IDfACL.DF_PERMIT_READ);
    addDenyPermitToAcl(id, "User1", IDfACL.DF_PERMIT_DELETE);
    addDenyPermitToAcl(id, "User2", IDfACL.DF_PERMIT_BROWSE);
    addDenyPermitToAcl(id, "User3", IDfACL.DF_PERMIT_WRITE);

    Map<DocId, Acl> namedResources = getAllAcls();
    Acl acl = namedResources.get(new DocId(id));
    assertEquals(ImmutableSet.of(new UserPrincipal("User4", "NS"),
        new UserPrincipal("User5", "NS")),
        acl.getPermitUsers());
    assertEquals(ImmutableSet.of(new UserPrincipal("User2", "NS")),
        acl.getDenyUsers());
    assertEquals(ImmutableSet.of(), acl.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl.getDenyGroups());
  }

  @Test
  public void testGroupAcls() throws Exception {
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

    Map<DocId, Acl> namedResources = getAllAcls();
    Acl acl = namedResources.get(new DocId(id));
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group1", "NS_Local"),
        new GroupPrincipal("Group2", "NS_Local")),
        acl.getPermitGroups());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group3", "NS_Local")),
        acl.getDenyGroups());
    assertEquals(ImmutableSet.of(new UserPrincipal("User1", "NS"),
        new UserPrincipal("User2", "NS")),
        acl.getPermitUsers());
    assertEquals(ImmutableSet.of(), acl.getDenyUsers());
  }

  @Test
  public void testDisabledUserAcls() throws Exception {
    insertUsers("User2", "User3", "User4", "User5");
    disableUsers("User2", "User4");
    String id = "4501081f80000100";
    createAcl(id);
    addAllowPermitToAcl(id, "User4", IDfACL.DF_PERMIT_WRITE);
    addAllowPermitToAcl(id, "User5", IDfACL.DF_PERMIT_READ);
    addDenyPermitToAcl(id, "User2", IDfACL.DF_PERMIT_READ);
    addDenyPermitToAcl(id, "User3", IDfACL.DF_PERMIT_READ);

    Map<DocId, Acl> namedResources = getAllAcls();
    Acl acl = namedResources.get(new DocId(id));
    assertEquals(ImmutableSet.of(new UserPrincipal("User5", "NS")),
        acl.getPermitUsers());
    assertEquals(ImmutableSet.of(new UserPrincipal("User3", "NS")),
        acl.getDenyUsers());
    assertEquals(ImmutableSet.of(), acl.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl.getDenyGroups());
  }

  @Test
  public void testDisabledGroupAcls() throws Exception {
    insertGroup("Group1", "User2", "User3");
    insertGroup("Group2", "User4", "User5");
    insertGroup("Group3", "User6", "User7");
    insertGroup("Group4", "User8", "User9");
    disableUsers("Group2", "Group3");
    String id = "4501081f80000101";
    createAcl(id);
    addAllowPermitToAcl(id, "Group1", IDfACL.DF_PERMIT_READ);
    addAllowPermitToAcl(id, "Group2", IDfACL.DF_PERMIT_WRITE);
    addDenyPermitToAcl(id, "Group3", IDfACL.DF_PERMIT_READ);
    addDenyPermitToAcl(id, "Group4", IDfACL.DF_PERMIT_READ);

    Map<DocId, Acl> namedResources = getAllAcls();
    Acl acl = namedResources.get(new DocId(id));
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group1", "NS_Local")),
        acl.getPermitGroups());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group4", "NS_Local")),
        acl.getDenyGroups());
    assertEquals(ImmutableSet.of(), acl.getPermitUsers());
    assertEquals(ImmutableSet.of(), acl.getDenyUsers());
  }

  @Test
  public void testGroupDmWorldAcl() throws Exception {
    insertUsers("User1", "User3");
    insertGroup("Group1", "User2", "User3");
    String id = "4501081f80000102";
    createAcl(id);
    addAllowPermitToAcl(id, "Group1", IDfACL.DF_PERMIT_BROWSE);
    addAllowPermitToAcl(id, "dm_world", IDfACL.DF_PERMIT_READ);
    addDenyPermitToAcl(id, "User1", IDfACL.DF_PERMIT_READ);
    addDenyPermitToAcl(id, "User3", IDfACL.DF_PERMIT_WRITE);

    Map<DocId, Acl> namedResources = getAllAcls();
    Acl acl = namedResources.get(new DocId(id));
    assertEquals(ImmutableSet.of(new GroupPrincipal("dm_world", "NS_Local")),
        acl.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl.getDenyGroups());
    assertEquals(ImmutableSet.of(), acl.getPermitUsers());
    assertEquals(ImmutableSet.of(new UserPrincipal("User1", "NS")),
        acl.getDenyUsers());
  }

  @Test
  public void testDomainForAclUser() throws Exception {
    insertUsers("User1", "User2", "User3", "User4", "User5");
    String id = "4501081f80000100";
    createAcl(id);
    addAllowPermitToAcl(id, "User4", IDfACL.DF_PERMIT_WRITE);
    addAllowPermitToAcl(id, "User5", IDfACL.DF_PERMIT_READ);
    addDenyPermitToAcl(id, "User1", IDfACL.DF_PERMIT_DELETE);
    addDenyPermitToAcl(id, "User2", IDfACL.DF_PERMIT_BROWSE);
    addDenyPermitToAcl(id, "User3", IDfACL.DF_PERMIT_WRITE);

    Map<DocId, Acl> namedResources = getAllAcls("ajax", 0);

    Acl acl = namedResources.get(new DocId(id));
    assertEquals(ImmutableSet.of(new UserPrincipal("ajax\\User4", "NS"),
        new UserPrincipal("ajax\\User5", "NS")),
        acl.getPermitUsers());
    assertEquals(ImmutableSet.of(new UserPrincipal("ajax\\User2", "NS")),
        acl.getDenyUsers());
  }

  @Test
  public void testDnsDomainForAclUser() throws Exception {
    insertUsers("User1", "User2", "User3", "User4", "User5");
    String id = "4501081f80000100";
    createAcl(id);
    addAllowPermitToAcl(id, "User4", IDfACL.DF_PERMIT_WRITE);
    addAllowPermitToAcl(id, "User5", IDfACL.DF_PERMIT_READ);
    addDenyPermitToAcl(id, "User1", IDfACL.DF_PERMIT_DELETE);
    addDenyPermitToAcl(id, "User2", IDfACL.DF_PERMIT_BROWSE);
    addDenyPermitToAcl(id, "User3", IDfACL.DF_PERMIT_WRITE);

    Map<DocId, Acl> namedResources = getAllAcls("ajax.example.com", 0);
    Acl acl = namedResources.get(new DocId(id));
    assertEquals(ImmutableSet.of(
        new UserPrincipal("ajax.example.com\\User4", "NS"),
        new UserPrincipal("ajax.example.com\\User5", "NS")),
        acl.getPermitUsers());
    assertEquals(ImmutableSet.of(
        new UserPrincipal("ajax.example.com\\User2", "NS")),
        acl.getDenyUsers());
  }

  @Test
  public void testDomainForAclGroup() throws Exception {
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

    Map<DocId, Acl> namedResources = getAllAcls("ajax", 0);
    Acl acl = namedResources.get(new DocId(id));
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group1", "NS_Local"),
        new GroupPrincipal("Group2", "NS_Local")),
        acl.getPermitGroups());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group3", "NS_Local")),
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
  public void testRequiredGroupSetAcl() throws Exception {
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

    Map<DocId, Acl> namedResources = getAllAcls();
    assertEquals(2, namedResources.size());

    Acl acl1 = namedResources.get(new DocId("45Acl0_reqGroupSet"));
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl1.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("GroupSet1", "NS_Local"),
        new GroupPrincipal("GroupSet2", "NS_Local")),
        acl1.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl1.getDenyGroups());

    Acl acl2 = namedResources.get(new DocId(id));
    assertEquals(new DocId("45Acl0_reqGroupSet"),
        acl2.getInheritFrom());
    assertEquals(InheritanceType.PARENT_OVERRIDES, acl2.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group1", "NS_Local"),
        new GroupPrincipal("Group2", "NS_Local")),
        acl2.getPermitGroups());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group3", "NS_Local")),
        acl2.getDenyGroups());
  }

  @Test
  public void testRequiredGroupsAcl() throws Exception {
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

    Map<DocId, Acl> namedResources = getAllAcls();
    assertEquals(4, namedResources.size());

    Acl acl1 = namedResources.get(new DocId("45Acl0_Group6"));
    assertEquals(new DocId("45Acl0_Group5"), acl1.getInheritFrom());
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl1.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group6", "NS_Local")),
        acl1.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl1.getDenyGroups());

    Acl acl2 = namedResources.get(new DocId("45Acl0_Group5"));
    assertEquals(new DocId("45Acl0_Group4"), acl2.getInheritFrom());
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl2.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group5", "NS_Local")),
        acl2.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl2.getDenyGroups());

    Acl acl3 = namedResources.get(new DocId("45Acl0_Group4"));
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl3.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group4", "NS_Local")),
        acl3.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl3.getDenyGroups());

    Acl acl4 = namedResources.get(new DocId(id));
    assertEquals(new DocId("45Acl0_Group6"), acl4.getInheritFrom());
    assertEquals(InheritanceType.PARENT_OVERRIDES, acl4.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group1", "NS_Local"),
        new GroupPrincipal("Group2", "NS_Local")),
        acl4.getPermitGroups());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group3", "NS_Local")),
        acl4.getDenyGroups());
  }

  @Test
  public void testRequiredGroupsAndSetsAcl() throws Exception {
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

    Map<DocId, Acl> namedResources = getAllAcls();
    assertEquals(5, namedResources.size());

    Acl acl1 = namedResources.get(new DocId("45Acl0_Group6"));
    assertEquals(new DocId("45Acl0_Group5"), acl1.getInheritFrom());
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl1.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group6", "NS_Local")),
        acl1.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl1.getDenyGroups());

    Acl acl2 = namedResources.get(new DocId("45Acl0_Group5"));
    assertEquals(new DocId("45Acl0_Group4"), acl2.getInheritFrom());
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl2.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group5", "NS_Local")),
        acl2.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl2.getDenyGroups());

    Acl acl3 = namedResources.get(new DocId("45Acl0_Group4"));
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl3.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group4", "NS_Local")),
        acl3.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl3.getDenyGroups());

    Acl acl4 = namedResources.get(new DocId("45Acl0_reqGroupSet"));
    assertEquals(new DocId("45Acl0_Group6"), acl4.getInheritFrom());
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl4.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("GroupSet1", "NS_Local"),
        new GroupPrincipal("GroupSet2", "NS_Local")),
        acl4.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl4.getDenyGroups());

    Acl acl5 = namedResources.get(new DocId(id));
    assertEquals(new DocId("45Acl0_reqGroupSet"),
        acl5.getInheritFrom());
    assertEquals(InheritanceType.PARENT_OVERRIDES, acl5.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group1", "NS_Local"),
        new GroupPrincipal("Group2", "NS_Local")),
        acl5.getPermitGroups());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group3", "NS_Local")),
        acl5.getDenyGroups());
  }

  // TODO(srinivas): we should check whether we have a test of non-existent
  // users and groups in permits and denies.
  @Test
  public void testMissingRequiredGroup() throws Exception {
    insertUsers("User1", "User2", "User3");
    insertGroup("Group1", "User2", "User3");

    String id = "45Acl0";
    createAcl(id);
    addAllowPermitToAcl(id, "Group1", IDfACL.DF_PERMIT_READ);
    addRequiredGroupToAcl(id, "GroupNotExists");

    Map<DocId, Acl> namedResources = getAllAcls();
    assertEquals(2, namedResources.size());

    Acl acl1 = namedResources.get(new DocId("45Acl0_GroupNotExists"));
    assertEquals(InheritanceType.AND_BOTH_PERMIT, acl1.getInheritanceType());
    assertEquals(ImmutableSet.of(), acl1.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl1.getDenyGroups());

    // Verify GroupNotExists group is not in permit or deny groups.
    Acl acl2 = namedResources.get(new DocId(id));
    assertEquals(new DocId("45Acl0_GroupNotExists"),
        acl2.getInheritFrom());
    assertEquals(InheritanceType.PARENT_OVERRIDES, acl2.getInheritanceType());
    assertEquals(ImmutableSet.of(new GroupPrincipal("Group1", "NS_Local")),
        acl2.getPermitGroups());
    assertEquals(ImmutableSet.of(), acl2.getDenyGroups());
  }

  @Test
  public void testAclMarkAllDocsPublic() throws Exception {
    DocumentumAdaptor adaptor = getObjectUnderTest(
        ImmutableMap.of("adaptor.markAllDocsAsPublic", MarkAllDocsPublic.TRUE));
    Map<DocId, Acl> aclMap = getAllAcls(adaptor, NO_EXCEPTION);
    assertNotNull(aclMap);
    assertTrue(aclMap.isEmpty());
  }

  @Test
  public void testAclCaseSensitivity_basic() throws Exception {
    createAcl("4501081f80000100");
    Map<DocId, Acl> aclMap = getAllAcls(getObjectUnderTest(), NO_EXCEPTION);
    Acl acl = aclMap.get(new DocId("4501081f80000100"));
    assertTrue("Expected everything-case-sensitive",
        acl.isEverythingCaseSensitive());
  }

  @Test
  public void testAclCaseSensitivity_required() throws Exception {
    insertUsers("User1", "User2", "User3");
    insertGroup("Group1", "User2", "User3");
    createAcl("4501081f80000100");
    addRequiredGroupToAcl("4501081f80000100", "Group1");
    Map<DocId, Acl> aclMap = getAllAcls(getObjectUnderTest(), NO_EXCEPTION);
    Acl acl = aclMap.get(new DocId("4501081f80000100_Group1"));
    assertTrue("Expected everything-case-sensitive",
        acl.isEverythingCaseSensitive());
  }

  @Test
  public void testAclCaseSensitivity_sensitive() throws Exception {
    createAcl("4501081f80000100");
    DocumentumAdaptor adaptor = getObjectUnderTest(
        ImmutableMap.of("adaptor.caseSensitivityType",
                        CaseSensitivityType.EVERYTHING_CASE_SENSITIVE));
    Map<DocId, Acl> aclMap = getAllAcls(adaptor, NO_EXCEPTION);
    Acl acl = aclMap.get(new DocId("4501081f80000100"));
    assertTrue("Expected everything-case-sensitive",
        acl.isEverythingCaseSensitive());
  }

  @Test
  public void testAclCaseSensitivity_insensitive() throws Exception {
    createAcl("4501081f80000100");
    DocumentumAdaptor adaptor = getObjectUnderTest(
        ImmutableMap.of("adaptor.caseSensitivityType",
                        CaseSensitivityType.EVERYTHING_CASE_INSENSITIVE));
    Map<DocId, Acl> aclMap = getAllAcls(adaptor, NO_EXCEPTION);
    Acl acl = aclMap.get(new DocId("4501081f80000100"));
    assertTrue("Expected everything-case-insensitive",
        acl.isEverythingCaseInsensitive());
  }

  @Test
  public void testAclCaseSensitivity_required_insensitive() throws Exception {
    insertUsers("User1", "User2", "User3");
    insertGroup("Group1", "User2", "User3");
    createAcl("4501081f80000100");
    addRequiredGroupToAcl("4501081f80000100", "Group1");
    DocumentumAdaptor adaptor = getObjectUnderTest(
        ImmutableMap.of("adaptor.caseSensitivityType",
                        CaseSensitivityType.EVERYTHING_CASE_INSENSITIVE));
    Map<DocId, Acl> aclMap = getAllAcls(adaptor, NO_EXCEPTION);
    Acl acl = aclMap.get(new DocId("4501081f80000100_Group1"));
    assertTrue("Expected everything-case-insensitive",
        acl.isEverythingCaseInsensitive());
  }

  private void insertAclAudit(String id, String auditObjId,
      String eventName, String date) throws SQLException {
    executeUpdate(String.format(
        "insert into dm_audittrail_acl(r_object_id, audited_obj_id, "
            + "event_name, time_stamp_utc) "
            + "values('%s', '%s', '%s', {ts '%s'})",
            id, auditObjId, eventName, date));
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

  private Map<DocId, Acl> testUpdateAcls(Checkpoint checkpoint,
      Set<DocId> expectedAclIds, Checkpoint expectedCheckpoint)
      throws DfException, IOException, InterruptedException {
    return testUpdateAcls(getObjectUnderTest(), checkpoint,
        NO_EXCEPTION, expectedAclIds, expectedCheckpoint);
  }

  private Map<DocId, Acl> testUpdateAcls(DocumentumAdaptor adaptor,
      Checkpoint checkpoint, DfException expectedCause,
      Set<DocId> expectedAclIds, Checkpoint expectedCheckpoint)
      throws DfException, IOException, InterruptedException {
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    adaptor.modifiedAclTraverser.setCheckpoint(checkpoint);
    try {
      adaptor.getModifiedDocIds(pusher);
      assertNull("Expected an exception at " + checkpoint, expectedCause);
    } catch (IOException e) {
      if (expectedCause == NO_EXCEPTION || expectedCause != e.getCause()) {
        throw e;
      }
    }
    assertEquals(expectedCheckpoint,
        adaptor.modifiedAclTraverser.getCheckpoint());

    Map<DocId, Acl> aclMap = pusher.getNamedResources();
    assertEquals(expectedAclIds, aclMap.keySet());
    return aclMap;
  }

  private void assertUsers(Set<UserPrincipal> actual, String... expected) {
    ImmutableSet.Builder<UserPrincipal> builder = ImmutableSet.builder();
    for (String user : expected) {
      builder.add(new UserPrincipal(user, "globalNS"));
    }
    assertEquals(builder.build(), actual);
  }

  @Test
  public void testUpdateAcls() throws Exception {
    createAcl("4501081f80000100");
    createAcl("4501081f80000101");
    String dateStr = getNowPlusMinutes(5);
    insertAclAudit("123", "4501081f80000100", "dm_save", dateStr);
    insertAclAudit("124", "4501081f80000101", "dm_saveasnew", dateStr);
    insertAclAudit("125", "4501081f80000102", "dm_destroy", dateStr);

    testUpdateAcls(Checkpoint.incremental(),
        ImmutableSet.of(
            new DocId("4501081f80000100"),
            new DocId("4501081f80000101"),
            new DocId("4501081f80000102")),
        new Checkpoint(dateStr, "125"));
  }

  @Test
  public void testUpdateAclsPrincipals() throws Exception {
    insertUsers("User1", "User2", "User3", "User4", "User5", "User6");
    String aclId1 = "4501081f80000100";
    String aclId2 = "4501081f80000101";
    String aclId3 = "4501081f80000102";
    createAcl(aclId1);
    addAllowPermitToAcl(aclId1, "User1", IDfACL.DF_PERMIT_WRITE);
    addAllowPermitToAcl(aclId1, "User2", IDfACL.DF_PERMIT_READ);
    addDenyPermitToAcl(aclId1, "User3", IDfACL.DF_PERMIT_READ);

    // Allowing BROWSE and denying WRITE are no-ops for the connector.
    createAcl(aclId2);
    addAllowPermitToAcl(aclId2, "User4", IDfACL.DF_PERMIT_WRITE);
    addAllowPermitToAcl(aclId2, "User5", IDfACL.DF_PERMIT_BROWSE);
    addDenyPermitToAcl(aclId2, "User6", IDfACL.DF_PERMIT_WRITE);

    String dateStr = getNowPlusMinutes(5);
    insertAclAudit("123", aclId1, "dm_save", dateStr);
    insertAclAudit("124", aclId2, "dm_saveasnew", dateStr);
    insertAclAudit("125", aclId3, "dm_destroy", dateStr);

    Map<DocId, Acl> aclMap = testUpdateAcls(Checkpoint.incremental(),
        ImmutableSet.of(
            new DocId(aclId1), new DocId(aclId2), new DocId(aclId3)),
        new Checkpoint(dateStr, "125"));

    Acl acl1 = aclMap.get(new DocId(aclId1));
    assertUsers(acl1.getPermitUsers(), "User1", "User2");
    assertUsers(acl1.getDenyUsers(), "User3");

    Acl acl2 = aclMap.get(new DocId(aclId2));
    assertUsers(acl2.getPermitUsers(), "User4");
    assertTrue(acl2.getDenyUsers().toString(), acl2.getDenyUsers().isEmpty());

    assertEquals(Acl.EMPTY, aclMap.get(new DocId(aclId3)));
  }

  @Test
  public void testUpdateAclsWithSameObjectId() throws Exception {
    createAcl("4501081f80000100");
    createAcl("4501081f80000101");
    String dateStr = getNowPlusMinutes(6);
    insertAclAudit("123", "4501081f80000100", "dm_saveasnew", dateStr);
    insertAclAudit("124", "4501081f80000100", "dm_save", dateStr);
    insertAclAudit("125", "4501081f80000100", "dm_save", dateStr);

    testUpdateAcls(Checkpoint.incremental(),
        ImmutableSet.of(new DocId("4501081f80000100")),
        new Checkpoint(dateStr, "125"));
  }

  @Test
  public void testPreviouslyUpdatedAcls() throws Exception {
    createAcl("4501081f80000100");
    createAcl("4501081f80000101");
    String dateStr = getNowPlusMinutes(-10);
    insertAclAudit("123", "4501081f80000100", "dm_save", dateStr);
    insertAclAudit("124", "4501081f80000101", "dm_saveasnew", dateStr);
    insertAclAudit("125", "4501081f80000102", "dm_destroy", dateStr);

    Checkpoint checkpoint = new Checkpoint(getNowPlusMinutes(0), "0");
    testUpdateAcls(checkpoint, ImmutableSet.<DocId>of(), checkpoint);
  }

  @Test
  public void testMultiUpdateAcls() throws Exception {
    createAcl("4501081f80000100");
    createAcl("4501081f80000101");
    createAcl("4501081f80000102");
    createAcl("4501081f80000103");
    String dateStr = getNowPlusMinutes(10);
    insertAclAudit("123", "4501081f80000100", "dm_save", dateStr);
    insertAclAudit("124", "4501081f80000101", "dm_saveasnew", dateStr);
    insertAclAudit("125", "4501081f80000102", "dm_saveasnew", dateStr);

    Checkpoint firstCheckpoint = new Checkpoint(dateStr, "125");
    testUpdateAcls(Checkpoint.incremental(),
        ImmutableSet.of(
            new DocId("4501081f80000100"),
            new DocId("4501081f80000101"),
            new DocId("4501081f80000102")),
        firstCheckpoint);

    dateStr = getNowPlusMinutes(15);
    insertAclAudit("126", "4501081f80000103", "dm_saveasnew", dateStr);
    insertAclAudit("127", "4501081f80000104", "dm_destroy", dateStr);

    testUpdateAcls(firstCheckpoint,
        ImmutableSet.of(
            new DocId("4501081f80000103"),
            new DocId("4501081f80000104")),
        new Checkpoint(dateStr, "127"));
  }

  @Test
  public void testUpdateAclsSaveBeforeDestroy() throws Exception {
    String dateStr = getNowPlusMinutes(10);
    insertAclAudit("124", "4501081f80000100", "dm_save", getNowPlusMinutes(5));
    insertAclAudit("125", "4501081f80000100", "dm_destroy", dateStr);

    Map<DocId, Acl> aclMap = testUpdateAcls(Checkpoint.incremental(),
        ImmutableSet.of(new DocId("4501081f80000100")),
        new Checkpoint(dateStr, "125"));
    assertEquals(ImmutableMap.of(new DocId("4501081f80000100"), Acl.EMPTY),
        aclMap);
  }

  @Test
  public void testUpdateAclsSaveBeforeDestroySeparately() throws Exception {
    String dateStr = getNowPlusMinutes(5);
    insertAclAudit("124", "4501081f80000100", "dm_save", dateStr);

    Map<DocId, Acl> aclMap = testUpdateAcls(Checkpoint.incremental(),
        ImmutableSet.of(new DocId("4501081f80000100")),
        new Checkpoint(dateStr, "124"));
    assertEquals(ImmutableMap.of(new DocId("4501081f80000100"), Acl.EMPTY),
        aclMap);

    dateStr = getNowPlusMinutes(10);
    insertAclAudit("125", "4501081f80000100", "dm_destroy", dateStr);

    aclMap = testUpdateAcls(Checkpoint.incremental(),
        ImmutableSet.of(new DocId("4501081f80000100")),
        new Checkpoint(dateStr, "125"));
    assertEquals(ImmutableMap.of(new DocId("4501081f80000100"), Acl.EMPTY),
        aclMap);
  }

  @Test
  public void testMultiUpdateAclsWithNoResults() throws Exception {
    createAcl("4501081f80000106");
    createAcl("4501081f80000107");
    String dateStr = getNowPlusMinutes(20);
    insertAclAudit("128", "4501081f80000106", "dm_saveasnew", dateStr);
    insertAclAudit("129", "4501081f80000107", "dm_saveasnew", dateStr);

    Checkpoint expectedCheckpoint = new Checkpoint(dateStr, "129");
    testUpdateAcls(Checkpoint.incremental(),
        ImmutableSet.of(
            new DocId("4501081f80000106"),
            new DocId("4501081f80000107")),
        expectedCheckpoint);

    testUpdateAcls(expectedCheckpoint, ImmutableSet.<DocId>of(),
        expectedCheckpoint);
  }

  private void testUpdateAclsExceptions(Iterator<Integer> failIterations,
      DfException expectedCause,
      Set<DocId> expectedAclIds, Checkpoint expectedCheckpoint)
      throws DfException, IOException, InterruptedException {
    DocumentumAdaptor adaptor = getObjectUnderTest(
        new ExceptionalResultSetTestProxies(
            "FROM dm_audittrail_acl", failIterations,
            (expectedCause != NO_EXCEPTION) ? expectedCause
            : new DfException("Recoverable exception should be handled")),
        ImmutableMap.<String, String>of());
    adaptor.modifiedAclTraverser.setSleeper(NO_SLEEP);
    testUpdateAcls(adaptor, Checkpoint.incremental(), expectedCause,
        expectedAclIds, expectedCheckpoint);
  }

  @Test
  public void testUpdateAclsFirstRowException() throws Exception {
    createAcl("4501081f80000100");
    createAcl("4501081f80000101");
    String dateStr = getNowPlusMinutes(5);
    insertAclAudit("123", "4501081f80000100", "dm_save", dateStr);
    insertAclAudit("124", "4501081f80000101", "dm_saveasnew", dateStr);
    insertAclAudit("125", "4501081f80000102", "dm_destroy", dateStr);

    testUpdateAclsExceptions(Iterators.singletonIterator(0),
        new DfException("Expected failure in first row"),
        ImmutableSet.<DocId>of(),
        Checkpoint.incremental());
  }

  @Test
  public void testUpdateAclsOtherRowsException() throws Exception {
    createAcl("4501081f80000100");
    createAcl("4501081f80000101");
    String dateStr = getNowPlusMinutes(5);
    insertAclAudit("123", "4501081f80000100", "dm_save", dateStr);
    insertAclAudit("124", "4501081f80000101", "dm_saveasnew", dateStr);
    insertAclAudit("125", "4501081f80000102", "dm_destroy", dateStr);

    testUpdateAclsExceptions(Iterators.cycle(1),
        NO_EXCEPTION,
        ImmutableSet.of(
            new DocId("4501081f80000100"),
            new DocId("4501081f80000101"),
            new DocId("4501081f80000102")),
        new Checkpoint(dateStr, "125"));
  }

  @Test
  public void testUpdateAclsPartialRowsException() throws Exception {
    createAcl("4501081f80000100");
    createAcl("4501081f80000101");
    String dateStr = getNowPlusMinutes(5);
    insertAclAudit("123", "4501081f80000100", "dm_save", dateStr);
    insertAclAudit("124", "4501081f80000101", "dm_saveasnew", dateStr);
    insertAclAudit("125", "4501081f80000102", "dm_destroy", dateStr);

    testUpdateAclsExceptions(Iterators.forArray(2, 0),
        new DfException("Expected Partial Rows Exception"),
        ImmutableSet.of(
            new DocId("4501081f80000100"),
            new DocId("4501081f80000101")),
        new Checkpoint(dateStr, "124"));
  }

  private void insertAuditTrailEvent(String date, String id, String eventName,
      String attributeList, String auditObjId, String chronicleId)
      throws SQLException {
    executeUpdate(String.format(
        "insert into dm_audittrail(time_stamp_utc, r_object_id, event_name, "
            + "attribute_list, audited_obj_id, chronicle_id) "
            + "values({ts '%s'},'%s', '%s', '%s', '%s',  '%s')", date, id,
        eventName, attributeList, auditObjId, chronicleId));
  }

  private void insertAuditTrailAclEvent(String date, String id,
      String auditObjId) throws SQLException {
    insertAuditTrailEvent(date, id, "dm_save", "acl_name=", auditObjId,
        auditObjId);
  }

  private void insertAuditTrailAclEvent(String date, String id,
      String auditObjId, String chronicleId) throws SQLException {
    insertAuditTrailEvent(date, id, "dm_save", "acl_name=", auditObjId,
        chronicleId);
  }

  private void testUpdatedPermissions(Checkpoint docCheckpoint,
      Checkpoint permissionsCheckpoint, List<Record> expectedDocIdlist,
      Checkpoint expectedCheckpoint)
          throws DfException, IOException, InterruptedException {
    DocumentumAdaptor adaptor = getObjectUnderTest();

    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    adaptor.modifiedDocumentTraverser.setCheckpoint(docCheckpoint);
    adaptor.modifiedPermissionsTraverser.setCheckpoint(permissionsCheckpoint);
    adaptor.getModifiedDocIds(pusher);

    assertEquals(expectedDocIdlist, pusher.getRecords());
    assertEquals(expectedCheckpoint,
        adaptor.modifiedPermissionsTraverser.getCheckpoint());
  }

  private Checkpoint insertTestDocuments() throws SQLException {
    String folderId = "0bd29";
    String folder = START_PATH;

    // To skip doc updates, set time for document creation 5 min earlier.
    String dateStr = getNowPlusMinutes(-5);
    insertFolder(dateStr, folderId, folder);
    insertDocument(dateStr, "09514", folder + "/file1", folderId);
    insertDocument(dateStr, "09515", folder + "/file2", folderId);
    insertDocument(dateStr, "09516", folder + "/file3", folderId);

    return new Checkpoint(dateStr, folderId);
  }

  @Test
  public void testUpdatedPermissions() throws Exception {
    Checkpoint docCheckpoint = insertTestDocuments();

    String dateStr = getNowPlusMinutes(5);
    insertAuditTrailAclEvent(dateStr, "5f123", "09514");
    insertAuditTrailAclEvent(dateStr, "5f124", "09515");
    insertAuditTrailAclEvent(dateStr, "5f125", "09516");

    testUpdatedPermissions(docCheckpoint, Checkpoint.incremental(),
        makeExpectedDocIds(START_PATH, "file1", "file2", "file3"),
        new Checkpoint(dateStr, "5f125"));
  }

  @Test
  public void testUpdatedPermissions_ModifiedCheckpoint() throws Exception {
    Checkpoint docCheckpoint = insertTestDocuments();

    String dateStr = getNowPlusMinutes(5);
    insertAuditTrailAclEvent(dateStr, "5f123", "09514");
    insertAuditTrailAclEvent(dateStr, "5f124", "09515");
    insertAuditTrailAclEvent(dateStr, "5f125", "09516");

    testUpdatedPermissions(docCheckpoint, new Checkpoint(dateStr, "5f123"),
        makeExpectedDocIds(START_PATH, "file2", "file3"),
        new Checkpoint(dateStr, "5f125"));
  }

  @Test
  public void testUpdatedPermissions_MultipleUpdates() throws Exception {
    Checkpoint docCheckpoint = insertTestDocuments();

    String dateStr = getNowPlusMinutes(5);
    insertAuditTrailAclEvent(getNowPlusMinutes(3), "5f123", "09514");
    insertAuditTrailAclEvent(getNowPlusMinutes(4), "5f124", "09514");
    insertAuditTrailAclEvent(getNowPlusMinutes(5), "5f125", "09514");
    insertAuditTrailAclEvent(getNowPlusMinutes(5), "5f126", "09515");

    testUpdatedPermissions(docCheckpoint, Checkpoint.incremental(),
        makeExpectedDocIds(START_PATH, "file1", "file2"),
        new Checkpoint(dateStr, "5f126"));
  }

  @Test
  public void testUpdatedPermissions_SameChronicleId() throws Exception {
    Checkpoint docCheckpoint = insertTestDocuments();

    String dateStr = getNowPlusMinutes(5);
    insertAuditTrailAclEvent(dateStr, "5f123", "09514", "09234");
    insertAuditTrailAclEvent(dateStr, "5f124", "09515", "09234");
    insertAuditTrailAclEvent(dateStr, "5f125", "09516", "09234");

    testUpdatedPermissions(docCheckpoint, Checkpoint.incremental(),
        makeExpectedDocIds(START_PATH, "file1"),
        new Checkpoint(dateStr, "5f125"));
  }

  @Test
  public void testUpdatedPermissions_EmptyResults() throws Exception {
    Checkpoint docCheckpoint = insertTestDocuments();

    String dateStr = getNowPlusMinutes(5);
    insertAuditTrailAclEvent(dateStr, "5f123", "09514");
    insertAuditTrailAclEvent(dateStr, "5f124", "09515");
    insertAuditTrailAclEvent(dateStr, "5f125", "09516");

    testUpdatedPermissions(docCheckpoint, new Checkpoint(dateStr, "5f125"),
        makeExpectedDocIds(START_PATH),
        new Checkpoint(dateStr, "5f125"));
  }

  @Test
  public void testUpdatedPermissions_MultiplePaths() throws Exception {
    // To skip doc updates, set time for document creation 5 min earlier.
    String min5back = getNowPlusMinutes(-5);
    insertFolder(min5back, "0bd30", START_PATH + "/folder1");
    insertFolder(min5back, "0bd31", START_PATH + "/folder2");
    insertFolder(min5back, "0bd32", START_PATH + "/folder/folder3");
    insertSysObject(min5back, "09514", "file1", START_PATH + "/folder1/file1,"
        + START_PATH + "/folder2/file1," + START_PATH + "/folder/folder3/file1",
        "dm_document", "0bd30", "0bd31", "0bd32");

    String dateStr = getNowPlusMinutes(5);
    insertAuditTrailAclEvent(dateStr, "5f123", "09514");

    testUpdatedPermissions(new Checkpoint(min5back, "0bd32"),
        Checkpoint.incremental(),
        makeExpectedDocIds(START_PATH, "folder1/file1", "folder2/file1",
            "folder/folder3/file1"), new Checkpoint(dateStr, "5f123"));
  }

  @Test
  public void testUpdatedPermissions_InvalidStartPath() throws Exception {
    // To skip doc updates, set time for document creation 5 min earlier.
    String min5back = getNowPlusMinutes(-5);
    insertFolder(min5back, "0bd30", START_PATH + "/folder1");
    insertFolder(min5back, "0bd31", START_PATH + "/folder2");
    insertFolder(min5back, "0bd32", "/Folder2/folder3");
    insertSysObject(min5back, "09514", "file1", START_PATH + "/folder1/file1,"
        + START_PATH + "/folder2/file1," + "/Folder2/folder3/file1",
        "dm_document", "0bd30", "0bd31", "0bd32");

    String dateStr = getNowPlusMinutes(5);
    insertAuditTrailAclEvent(dateStr, "5f123", "09514");

    testUpdatedPermissions(new Checkpoint(min5back, "0bd32"),
        Checkpoint.incremental(),
        makeExpectedDocIds(START_PATH, "folder1/file1", "folder2/file1"),
        new Checkpoint(dateStr, "5f123"));
  }

  @Test
  public void testUpdatedPermissions_DocAndPermissions() throws Exception {
    Checkpoint docCheckpoint = new Checkpoint(getNowPlusMinutes(-5), "5f125");
    String dateStr = getNowPlusMinutes(5);
    String folderId = "0bd29";
    String folder = START_PATH;
    insertFolder(getNowPlusMinutes(-5), folderId, folder);
    insertSysObject(dateStr, "09514", "file1", START_PATH + "/file1",
        "dm_document", "0bd29");
    insertAuditTrailAclEvent(dateStr, "5f123", "09514");

    testUpdatedPermissions(docCheckpoint, Checkpoint.incremental(),
        makeExpectedDocIds(START_PATH, "file1", "file1"),
        new Checkpoint(dateStr, "5f123"));
  }

  @Test
  public void testUpdatedPermissions_AclNonAclEvents() throws Exception {
    Checkpoint docCheckpoint = insertTestDocuments();
    String dateStr = getNowPlusMinutes(5);

    insertAuditTrailEvent(dateStr, "5f123", "dm_save", "acl_name=",
        "09514", "09514");
    insertAuditTrailEvent(dateStr, "5f124", "dm_link", "acl_name=",
        "09515", "09515");
    insertAuditTrailEvent(dateStr, "5f125", "dm_save", "object_name=",
        "09516", "09516");
    insertAuditTrailEvent(dateStr, "5f126", "dm_link", "object_name=",
        "09517", "09517");

    Checkpoint checkPoint = Checkpoint.incremental();
    testUpdatedPermissions(docCheckpoint, checkPoint,
        makeExpectedDocIds(START_PATH, "file1"),
        new Checkpoint(dateStr, "5f123"));
  }

  private void testUpdatePermissionsExceptions(
      Iterator<Integer> failIterations,
      DfException expectedCause, List<Record> expectedRecords,
      Checkpoint expectedCheckpoint) throws Exception {
    Checkpoint docCheckpoint = insertTestDocuments();
    DocumentumAdaptor adaptor =
        getObjectUnderTest(new ExceptionalResultSetTestProxies(
            "FROM dm_sysobject s, dm_audittrail a", failIterations,
            (expectedCause != NO_EXCEPTION) ? expectedCause
            : new DfException("Recoverable exception should be handled")),
            ImmutableMap.<String, String>of());
    adaptor.modifiedPermissionsTraverser.setSleeper(NO_SLEEP);
    assertEquals(expectedRecords,
        getModifiedDocIdsPushed(adaptor, docCheckpoint, expectedCause));
    assertEquals(expectedCheckpoint,
        adaptor.modifiedPermissionsTraverser.getCheckpoint());
  }

  @Test
  public void testUpdatePermissionsFirstRowException()
      throws Exception {
    String dateStr = getNowPlusMinutes(5);
    insertAuditTrailAclEvent(dateStr, "5f123", "09514");
    insertAuditTrailAclEvent(dateStr, "5f124", "09515");
    insertAuditTrailAclEvent(dateStr, "5f125", "09516");

    testUpdatePermissionsExceptions(Iterators.singletonIterator(0),
        new DfException("Expected failure in first row"),
        ImmutableList.<Record>of(), Checkpoint.incremental());
  }

  @Test
  public void testUpdatePermissionsOtherRowsException()
      throws Exception {
    String dateStr = getNowPlusMinutes(5);
    insertAuditTrailAclEvent(dateStr, "5f123", "09514");
    insertAuditTrailAclEvent(dateStr, "5f124", "09515");
    insertAuditTrailAclEvent(dateStr, "5f125", "09516");

    testUpdatePermissionsExceptions(Iterators.cycle(1),
        NO_EXCEPTION,
        makeExpectedDocIds(START_PATH, "file1", "file2", "file3"),
        new Checkpoint(dateStr, "5f125"));
  }

  @Test
  public void testUpdatePermissionsPartialRowsException()
      throws Exception {
    String dateStr = getNowPlusMinutes(5);
    insertAuditTrailAclEvent(dateStr, "5f123", "09514");
    insertAuditTrailAclEvent(dateStr, "5f124", "09515");
    insertAuditTrailAclEvent(dateStr, "5f125", "09516");

    testUpdatePermissionsExceptions(Iterators.forArray(2, 0),
        new DfException("Expected Partial Rows Exception"),
        makeExpectedDocIds(START_PATH, "file1", "file2"),
        new Checkpoint(dateStr, "5f124"));
  }

  @Test
  public void testCheckpoint() throws Exception {
    Checkpoint checkpoint = Checkpoint.incremental();
    assertEquals("0", checkpoint.getObjectId());
    assertNotNull(checkpoint.getLastModified());
    assertTrue(checkpoint.equals(checkpoint));

    checkpoint = new Checkpoint("foo", "bar");
    assertEquals("foo", checkpoint.getLastModified());
    assertEquals("bar", checkpoint.getObjectId());
    assertTrue(checkpoint.equals(checkpoint));
    assertTrue(checkpoint.equals(new Checkpoint("foo", "bar")));
    assertFalse(checkpoint.equals(null));
    assertFalse(checkpoint.equals(Checkpoint.incremental()));
    assertFalse(checkpoint.equals(new Checkpoint("foo", "xyzzy")));
  }

  private Map<GroupPrincipal, ? extends Collection<Principal>> getGroups()
      throws DfException, IOException, InterruptedException {
    return getGroups(ImmutableMap.<String, String>of());
  }

  private Map<GroupPrincipal, ? extends Collection<Principal>> getGroups(
      Map<String, ?> configOverrides)
      throws DfException, IOException, InterruptedException {
    return getGroups(getObjectUnderTestNamespaces(
        new H2BackedTestProxies(), configOverrides), null);
  }

  private Map<GroupPrincipal, ? extends Collection<Principal>> getGroups(
      DocumentumAdaptor adaptor, DfException expectedCause)
      throws DfException, IOException, InterruptedException {
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    try {
      adaptor.getDocIds(pusher);
      assertNull("Expected an exception: " + expectedCause, expectedCause);
    } catch (IOException e) {
      if (expectedCause == NO_EXCEPTION || expectedCause != e.getCause()) {
        throw e;
      }
    }
    return pusher.getGroups();
  }

  /* Filters the 'dm_world' group out of the map of groups. */
  private <T> Map<GroupPrincipal, T> filterDmWorld(Map<GroupPrincipal, T> map) {
    return Maps.filterKeys(map, new Predicate<GroupPrincipal>() {
        @Override
        public boolean apply(GroupPrincipal principal) {
          return !"dm_world".equals(principal.getName());
        }
      });
  }

  @Test
  public void testGetGroupsMarkAllDocsPublic() throws Exception {
    insertUsers("User1", "User2", "User3", "User4", "User5");
    insertGroup("Group1", "User1", "User2", "User3");
    insertGroup("Group2", "User3", "User4", "User5");

    // If all docs are public, no groups should be sent.
    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of();

    assertEquals(expected,
        getGroups(ImmutableMap.of("adaptor.markAllDocsAsPublic", "true")));
  }

  @Test
  public void testGetGroupsDmWorldOnly() throws Exception {
    insertUsers("User1", "User2", "User3", "User4", "User5");

    // The only group should be the virtual group, dm_world, which consists
    // of all users.
    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of(new GroupPrincipal("dm_world", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User1", "NS"),
                            new UserPrincipal("User2", "NS"),
                            new UserPrincipal("User3", "NS"),
                            new UserPrincipal("User4", "NS"),
                            new UserPrincipal("User5", "NS")));

    // Fetch all the dm_world members in various sized batches.
    // Note: a batch size of 0, means no batching.
    for (int batchSize = 0; batchSize <= expected.size() + 1; batchSize++) {
      assertEquals("batchSize: " + batchSize, expected,
          getGroups(ImmutableMap.of("documentum.queryBatchSize", batchSize)));
    }
  }

  private void testDmWorldExceptions(Iterator<Integer> failIterations,
      Map<String, ?> configOverrides,
      DfException expectedCause,
      Map<GroupPrincipal, ? extends Collection<? extends Principal>>
      expectedGroups) throws DfException, IOException, InterruptedException {
    DocumentumAdaptor adaptor = getObjectUnderTestNamespaces(
        new ExceptionalResultSetTestProxies(
            "FROM dm_user", failIterations,
            (expectedCause != NO_EXCEPTION) ? expectedCause
            : new DfException("Recoverable exception should be handled")),
        configOverrides);
    adaptor.dmWorldTraverser.setSleeper(NO_SLEEP);
    assertEquals(expectedGroups, getGroups(adaptor, expectedCause));
  }

  @Test
  public void testDmWorldTraversalFirstRowException() throws Exception {
    insertUsers("User1", "User2", "User3", "User4", "User5");

    testDmWorldExceptions(Iterators.singletonIterator(0),
        ImmutableMap.<String, String>of(),
        new DfException("Expected failure in first user"),
        ImmutableMap.<GroupPrincipal, Set<Principal>>of());
  }

  @Test
  public void testDmWorldTraversalPartialRowExceptions() throws Exception {
    insertUsers("User1", "User2", "User3", "User4", "User5");

    // Double failure on User3 should abort effort to read all the users.
    testDmWorldExceptions(Iterators.forArray(2, 0),
        ImmutableMap.<String, String>of(),
        new DfException("Expected Partial Row Exception"),
        ImmutableMap.<GroupPrincipal, Set<Principal>>of());
  }

  @Test
  public void testDmWorldTraversalOtherRowsExceptions() throws Exception {
    insertUsers("User1", "User2", "User3", "User4", "User5");

    // The only group should be the virtual group, dm_world, which consists
    // of all users.
    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of(new GroupPrincipal("dm_world", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User1", "NS"),
                            new UserPrincipal("User2", "NS"),
                            new UserPrincipal("User3", "NS"),
                            new UserPrincipal("User4", "NS"),
                            new UserPrincipal("User5", "NS")));

    // Fetch all the dm_world members in various sized batches, failing
    // while iterating over the results in each batch.
    // Note: a batch size of 0, means no batching.
    for (int batchSize = 0; batchSize <= expected.size() + 1; batchSize++) {
      int maxBatchSize = (batchSize == 0) ? expected.size() : batchSize;
      for (int failIter = 1; failIter <= maxBatchSize; failIter++) {
        testDmWorldExceptions(Iterators.cycle(failIter),
            ImmutableMap.of("documentum.queryBatchSize", batchSize),
            NO_EXCEPTION,
            expected);
      }
    }
  }

  @Test
  public void testGetGroupsUserMembersOnly() throws Exception {
    insertUsers("User1", "User2", "User3", "User4", "User5");
    insertGroup("Group1", "User1", "User2", "User3");
    insertGroup("Group2", "User3", "User4", "User5");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of(new GroupPrincipal("Group1", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User1", "NS"),
                            new UserPrincipal("User2", "NS"),
                            new UserPrincipal("User3", "NS")),
            new GroupPrincipal("Group2", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User3", "NS"),
                            new UserPrincipal("User4", "NS"),
                            new UserPrincipal("User5", "NS")));

    assertEquals(expected, filterDmWorld(getGroups()));
  }

  @Test
  public void testGetGroupsInvalidMembers() throws Exception {
    insertUsers("User1", "User3", "User5");
    insertGroup("Group1", "User1", "User2", "User3");
    insertGroup("Group2", "User3", "User4", "User5");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of(new GroupPrincipal("Group1", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User1", "NS"),
                            new UserPrincipal("User3", "NS")),
            new GroupPrincipal("Group2", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User3", "NS"),
                            new UserPrincipal("User5", "NS")));

    assertEquals(expected, filterDmWorld(getGroups()));
  }

  @Test
  public void testGetGroupsDisabledMembers() throws Exception {
    insertUsers("User1", "User2", "User3", "User4", "User5", "User6", "User7");
    insertGroup("Group1", "User1", "User2", "User3");
    insertGroup("Group2", "User3", "User4", "User5");
    insertGroup("Group3", "User5", "User6", "User7");
    disableUsers("User2", "User4", "User6", "Group2");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of(new GroupPrincipal("Group1", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User1", "NS"),
                            new UserPrincipal("User3", "NS")),
            new GroupPrincipal("Group3", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User5", "NS"),
                            new UserPrincipal("User7", "NS")));

    assertEquals(expected, filterDmWorld(getGroups()));
  }

  @Test
  public void testGetGroupsEmptyGroup() throws Exception {
    insertUsers("User1", "User3", "User5");
    insertGroup("Group1", "User1", "User2", "User3");
    insertGroup("Group2");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of(new GroupPrincipal("Group1", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User1", "NS"),
                            new UserPrincipal("User3", "NS")),
            new GroupPrincipal("Group2", "NS_Local"),
            ImmutableSet.<Principal>of());

    assertEquals(expected, filterDmWorld(getGroups()));
  }

  @Test
  public void testGetGroupsUserAndGroupMembers() throws Exception {
    insertUsers("User1", "User2", "User3", "User4", "User5");
    insertGroup("Group1", "User1", "User2", "User3");
    insertGroup("Group2", "Group1", "User4", "User5");
    insertGroup("Group3", "Group2", "User1", "User5");
    insertGroup("Group4", "User1", "User2", "User3", "User4");
    insertGroup("Group5", "Group1", "Group2");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
       expected = ImmutableMap.of(new GroupPrincipal("Group1", "NS_Local"),
           ImmutableSet.of(new UserPrincipal("User1", "NS"),
                           new UserPrincipal("User2", "NS"),
                           new UserPrincipal("User3", "NS")),
           new GroupPrincipal("Group2", "NS_Local"),
           ImmutableSet.of(new GroupPrincipal("Group1", "NS_Local"),
                           new UserPrincipal("User4", "NS"),
                           new UserPrincipal("User5", "NS")),
           new GroupPrincipal("Group3", "NS_Local"),
           ImmutableSet.of(new GroupPrincipal("Group2", "NS_Local"),
                           new UserPrincipal("User1", "NS"),
                           new UserPrincipal("User5", "NS")),
           new GroupPrincipal("Group4", "NS_Local"),
           ImmutableSet.of(new UserPrincipal("User1", "NS"),
                           new UserPrincipal("User2", "NS"),
                           new UserPrincipal("User3", "NS"),
                           new UserPrincipal("User4", "NS")),
           new GroupPrincipal("Group5", "NS_Local"),
           ImmutableSet.of(new GroupPrincipal("Group1", "NS_Local"),
                           new GroupPrincipal("Group2", "NS_Local")));

    // Fetch all the groups in various sized batches.
    // Note: a batch size of 0, means no batching.
    for (int batchSize = 0; batchSize <= expected.size() + 1; batchSize++) {
      assertEquals("batchSize: " + batchSize, expected, filterDmWorld(
          getGroups(ImmutableMap.of("documentum.queryBatchSize", batchSize))));
    }
  }

  private void testGetGroupsExceptions(Iterator<Integer> failIterations,
      String queryFragment, Map<String, ?> configOverrides,
      DfException expectedCause,
      Map<GroupPrincipal, ? extends Collection<? extends Principal>>
      expectedGroups) throws DfException, IOException, InterruptedException {
    DocumentumAdaptor adaptor = getObjectUnderTestNamespaces(
        new ExceptionalResultSetTestProxies(
            queryFragment, failIterations,
            (expectedCause != NO_EXCEPTION) ? expectedCause
            : new DfException("Recoverable exception should be handled")),
        configOverrides);
    adaptor.groupTraverser.setSleeper(NO_SLEEP);
    assertEquals(expectedGroups,
        filterDmWorld(getGroups(adaptor, expectedCause)));
  }

  @Test
  public void testGetGroupsThrownExceptionInFirstCandidate()
      throws Exception {
    insertUsers("User1", "User2");
    insertGroup("Group1", "User1");
    insertGroup("Group2", "User2");

    testGetGroupsExceptions(Iterators.singletonIterator(0),
        "SELECT r_object_id FROM dm_group",
        ImmutableMap.of("documentum.queryBatchSize", 10),
        new DfException("Expected failure in first candidate"),
        ImmutableMap.<GroupPrincipal, Set<Principal>>of());
  }

  @Test
  public void testGetGroupsThrownExceptionInCandidates()
      throws Exception {
    insertUsers("User1", "User2", "User3", "User4", "User5");
    insertGroup("Group1", "User1");
    insertGroup("Group2", "User2");
    insertGroup("Group3", "User3");
    insertGroup("Group4", "User4");
    insertGroup("Group5", "User5");

    testGetGroupsExceptions(Iterators.cycle(2),
        "SELECT r_object_id FROM dm_group",
        ImmutableMap.of("documentum.queryBatchSize", 10),
        NO_EXCEPTION,
        ImmutableMap.of(
           new GroupPrincipal("Group1", "NS_Local"),
               ImmutableSet.of(new UserPrincipal("User1", "NS")),
           new GroupPrincipal("Group2", "NS_Local"),
               ImmutableSet.of(new UserPrincipal("User2", "NS")),
           new GroupPrincipal("Group3", "NS_Local"),
               ImmutableSet.of(new UserPrincipal("User3", "NS")),
           new GroupPrincipal("Group4", "NS_Local"),
               ImmutableSet.of(new UserPrincipal("User4", "NS")),
           new GroupPrincipal("Group5", "NS_Local"),
               ImmutableSet.of(new UserPrincipal("User5", "NS"))));
  }

  @Test
  public void testGetGroupsThrownExceptionBetweenGroups()
      throws Exception {
    insertUsers("User1", "User2", "User3", "User4", "User5");
    insertGroup("Group1", "User1");
    insertGroup("Group2", "User2");
    insertGroup("Group3", "User3");
    insertGroup("Group4", "User4");
    insertGroup("Group5", "User5");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
       expected = ImmutableMap.of(
           new GroupPrincipal("Group1", "NS_Local"),
               ImmutableSet.of(new UserPrincipal("User1", "NS")),
           new GroupPrincipal("Group2", "NS_Local"),
               ImmutableSet.of(new UserPrincipal("User2", "NS")),
           new GroupPrincipal("Group3", "NS_Local"),
               ImmutableSet.of(new UserPrincipal("User3", "NS")),
           new GroupPrincipal("Group4", "NS_Local"),
               ImmutableSet.of(new UserPrincipal("User4", "NS")),
           new GroupPrincipal("Group5", "NS_Local"),
               ImmutableSet.of(new UserPrincipal("User5", "NS")));

    // Fetch all the groups in various sized batches, throwing an exception
    // after each group. Each group has a single member, so each group is a
    // single row in the result set.
    // Note: a batch size of 0, means no batching.
    for (int batchSize = 0; batchSize <= expected.size() + 1; batchSize++) {
      testGetGroupsExceptions(Iterators.cycle(2),
          "ENABLE(ROW_BASED)",
          ImmutableMap.of("documentum.queryBatchSize", batchSize),
          NO_EXCEPTION,
          expected);
    }
  }

  @Test
  public void testGetGroupsThrownExceptionInFirstGroup()
      throws Exception {
    insertUsers("User1", "User2", "User3", "User4", "User5");
    insertGroup("Group1", "User1", "User2", "User3");
    insertGroup("Group2", "User4", "User5");

    testGetGroupsExceptions(Iterators.singletonIterator(1),
        "ENABLE(ROW_BASED)",
        ImmutableMap.<String, String>of(),
        new DfException("Expected failure in first group"),
        ImmutableMap.<GroupPrincipal, Set<Principal>>of());
  }

  @Test
  public void testGetGroupsThrownExceptionMidGroup()
      throws Exception {
    insertUsers("User1", "User2", "User3", "User4", "User5");
    insertGroup("Group1", "User1", "User2", "User3");
    insertGroup("Group2", "User1", "User2", "User3", "User4");
    insertGroup("Group5", "User5");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
       expected = ImmutableMap.of(
           new GroupPrincipal("Group1", "NS_Local"),
               ImmutableSet.of(new UserPrincipal("User1", "NS"),
                               new UserPrincipal("User2", "NS"),
                               new UserPrincipal("User3", "NS")),
           new GroupPrincipal("Group2", "NS_Local"),
               ImmutableSet.of(new UserPrincipal("User1", "NS"),
                               new UserPrincipal("User2", "NS"),
                               new UserPrincipal("User3", "NS"),
                               new UserPrincipal("User4", "NS")),
           new GroupPrincipal("Group5", "NS_Local"),
               ImmutableSet.of(new UserPrincipal("User5", "NS")));

    // Fetch all the groups in various sized batches, throwing an exception
    // mid-group. Note: a batch size of 0, means no batching.
    for (int batchSize = 0; batchSize <= expected.size() + 1; batchSize += 2) {
      testGetGroupsExceptions(Iterators.cycle(5),
          "ENABLE(ROW_BASED)",
          ImmutableMap.of("documentum.queryBatchSize", batchSize),
          NO_EXCEPTION,
          expected);
    }
  }

  @Test
  public void testGetGroupsPartialRowsException() throws Exception {
    insertUsers("User1", "User2", "User3", "User4", "User5");
    insertGroup("Group1", "User1");
    insertGroup("Group2", "User1", "User2", "User3", "User4");
    insertGroup("Group5", "User5");

    // This should fail on Group2 the first time, and again on retry,
    // so only the first group will get pushed.
    testGetGroupsExceptions(Iterators.cycle(2),
        "ENABLE(ROW_BASED)",
        ImmutableMap.<String, String>of(),
        new DfException("Expected repeat failure"),
        ImmutableMap.of(new GroupPrincipal("Group1", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User1", "NS"))));
  }

  @Test
  public void testGetGroupsDifferentMemberLoginName() throws Exception {
    insertUsers("User1", "User2");
    executeUpdate("insert into dm_user(user_name, user_login_name) "
        + "values('User3', 'UserTres')");
    insertGroup("Group1", "User1", "User2", "User3");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of(new GroupPrincipal("Group1", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User1", "NS"),
                            new UserPrincipal("User2", "NS"),
                            new UserPrincipal("UserTres", "NS")));

    assertEquals(expected, filterDmWorld(getGroups()));
  }

  @Test
  public void testGetGroupsDifferentGroupLoginName() throws Exception {
    insertUsers("User1", "User2");
    executeUpdate(
        "insert into dm_user(user_name, user_login_name, r_is_group) "
        + "values('Group1', 'GroupUno', TRUE)");
    executeUpdate("insert into dm_group(r_object_id, group_name, users_names) "
        + "values ('12Group1', 'Group1', 'User1'),"
        + " ('12Group1', 'Group1', 'User2')");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of(new GroupPrincipal("GroupUno", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User1", "NS"),
                            new UserPrincipal("User2", "NS")));

    assertEquals(expected, filterDmWorld(getGroups()));
  }

  @Test
  public void testGetGroupsMemberLdapDn() throws Exception {
    insertUsers("User1", "User2");
    executeUpdate("insert into dm_user(user_name, user_login_name, "
        + "user_source, user_ldap_dn, r_is_group) values('User3', 'User3', "
        + "'LDAP', 'cn=User3,dc=test,dc=com', TRUE)");
    insertGroup("Group1", "User1", "User2", "User3");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of(new GroupPrincipal("Group1", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User1", "NS"),
                            new UserPrincipal("User2", "NS"),
                            new UserPrincipal("test\\User3", "NS")));

    assertEquals(expected, filterDmWorld(getGroups()));
  }

  @Test
  public void testGetGroupsGroupLdapDn() throws Exception {
    insertUsers("User1", "User2");
    executeUpdate("insert into dm_user(user_name, user_login_name, "
        + "user_source, user_ldap_dn) values('Group1', 'Group1', 'LDAP', "
        + "'cn=Group1,dc=test,dc=com')");
    executeUpdate("insert into dm_group(r_object_id, group_name, group_source,"
        + " users_names) values ('12Group1', 'Group1', 'LDAP', 'User1'),"
        + " ('12Group1', 'Group1', 'LDAP', 'User2')");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected =
            ImmutableMap.of(new GroupPrincipal("test\\Group1", "NS"),
                ImmutableSet.of(new UserPrincipal("User1", "NS"),
                                new UserPrincipal("User2", "NS")));

    assertEquals(expected, filterDmWorld(getGroups()));
  }

  @Test
  public void testGetGroupsWindowsDomainUsers() throws Exception {
    insertUsers("User1", "User2", "User3", "User4", "User5");
    insertGroup("Group1", "User1", "User2", "User3");
    insertGroup("Group2", "Group1", "User4", "User5");

   ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
       expected = ImmutableMap.of(new GroupPrincipal("Group1", "NS_Local"),
           ImmutableSet.of(new UserPrincipal("TEST\\User1", "NS"),
                           new UserPrincipal("TEST\\User2", "NS"),
                           new UserPrincipal("TEST\\User3", "NS")),
           new GroupPrincipal("Group2", "NS_Local"),
           ImmutableSet.of(new GroupPrincipal("Group1", "NS_Local"),
                           new UserPrincipal("TEST\\User4", "NS"),
                           new UserPrincipal("TEST\\User5", "NS")));

   assertEquals(expected, filterDmWorld(
       getGroups(ImmutableMap.of("documentum.windowsDomain", "TEST"))));
  }

  @Test
  public void testGetGroupsLocalAndGlobalGroups() throws Exception {
    insertUsers("User1", "User2", "User3", "User4", "User5");
    insertGroup("Group1", "User1", "User2", "User3");
    insertLdapGroup("Group2", "User3", "User4", "User5");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of(new GroupPrincipal("Group1", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User1", "NS"),
                            new UserPrincipal("User2", "NS"),
                            new UserPrincipal("User3", "NS")),
            new GroupPrincipal("Group2", "NS"),
            ImmutableSet.of(new UserPrincipal("User3", "NS"),
                            new UserPrincipal("User4", "NS"),
                            new UserPrincipal("User5", "NS")));

    assertEquals(expected, filterDmWorld(getGroups()));
  }

  @Test
  public void testGetGroupsGlobalGroupMembers() throws Exception {
    insertUsers("User1", "User2", "User3", "User4", "User5");
    insertLdapGroup("Group1", "User1", "User2", "User3");
    insertGroup("Group2", "Group1", "User4", "User5");

   ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
       expected = ImmutableMap.of(new GroupPrincipal("Group1", "NS"),
           ImmutableSet.of(new UserPrincipal("User1", "NS"),
                           new UserPrincipal("User2", "NS"),
                           new UserPrincipal("User3", "NS")),
           new GroupPrincipal("Group2", "NS_Local"),
           ImmutableSet.of(new GroupPrincipal("Group1", "NS"),
                           new UserPrincipal("User4", "NS"),
                           new UserPrincipal("User5", "NS")));

    assertEquals(expected, filterDmWorld(getGroups()));
  }

  @Test
  public void testGetGroupsLocalGroupsOnly() throws Exception {
    insertUsers("User1", "User2", "User3", "User4", "User5");
    insertLdapGroup("Group1", "User1", "User2", "User3");
    insertGroup("Group2", "Group1", "User4", "User5");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
       expected = ImmutableMap.of(new GroupPrincipal("Group2", "NS_Local"),
           ImmutableSet.of(new GroupPrincipal("Group1", "NS"),
                           new UserPrincipal("User4", "NS"),
                           new UserPrincipal("User5", "NS")));

    assertEquals(expected, filterDmWorld(
        getGroups(ImmutableMap.of("documentum.pushLocalGroupsOnly", "true"))));
  }

  private void insertModifiedGroup(String lastModified, String groupName,
      String... members) throws SQLException {
    insertGroupEx(lastModified, "", groupName, members);
  }

  private void checkModifiedGroupsPushed(LocalGroupsOnly localGroupsOnly,
      Checkpoint checkpoint,
      Map<GroupPrincipal, ? extends Collection<? extends Principal>>
      expectedGroups, Checkpoint expectedCheckpoint)
      throws DfException, IOException, InterruptedException {
    checkModifiedGroupsPushed(getObjectUnderTestNamespaces(
        ImmutableMap.of("documentum.pushLocalGroupsOnly", localGroupsOnly)),
        checkpoint, NO_EXCEPTION, expectedGroups, expectedCheckpoint);
  }

  private void checkModifiedGroupsPushed(DocumentumAdaptor adaptor,
      Checkpoint checkpoint, DfException expectedCause,
      Map<GroupPrincipal, ? extends Collection<? extends Principal>>
      expectedGroups, Checkpoint expectedCheckpoint)
      throws DfException, IOException, InterruptedException {
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    adaptor.modifiedGroupTraverser.setCheckpoint(checkpoint);

    try {
      adaptor.getModifiedDocIds(pusher);
      assertNull("Expected an exception at " + checkpoint, expectedCause);
    } catch (IOException e) {
      if (expectedCause == NO_EXCEPTION || expectedCause != e.getCause()) {
        throw e;
      }
    }

    assertEquals(expectedGroups, pusher.getGroups());
    assertEquals(expectedCheckpoint,
        adaptor.modifiedGroupTraverser.getCheckpoint());
  }

  @Test
  public void testGetGroupUpdatesNoDmWorld() throws Exception {
    insertUsers("User1", "User2", "User3", "User4", "User5");

    // The virtual group, dm_world, should not be pushed for updates.
    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
      expected = ImmutableMap.<GroupPrincipal, Collection<Principal>>of();

    Checkpoint checkpoint = Checkpoint.incremental();
    checkModifiedGroupsPushed(LocalGroupsOnly.FALSE, checkpoint, expected,
          checkpoint);
  }

  @Test
  public void testGetGroupUpdatesAllNew() throws Exception {
    insertUsers("User1", "User2");
    insertModifiedGroup(FEB_1970, "Group2", "User2");
    insertModifiedGroup(MAR_1970, "Group1", "User1");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of(new GroupPrincipal("Group1", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User1", "NS")),
            new GroupPrincipal("Group2", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User2", "NS")));

    checkModifiedGroupsPushed(LocalGroupsOnly.FALSE,
        new Checkpoint(JAN_1970, "0"), expected,
        new Checkpoint(MAR_1970, "12Group1"));
  }

  @Test
  public void testGetGroupUpdatesSomeNew() throws Exception {
    insertUsers("User1", "User2");
    insertModifiedGroup(JAN_1970, "Group0", "User2");
    insertModifiedGroup(FEB_1970, "Group2", "User2");
    insertModifiedGroup(MAR_1970, "Group1", "User1");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of(new GroupPrincipal("Group1", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User1", "NS")),
            new GroupPrincipal("Group2", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User2", "NS")));

    checkModifiedGroupsPushed(LocalGroupsOnly.FALSE,
        new Checkpoint(JAN_1970, "12Group0"), expected,
        new Checkpoint(MAR_1970, "12Group1"));
  }

  @Test
  public void testGetGroupUpdatesNoneNew() throws Exception {
    insertUsers("User1", "User2");
    insertModifiedGroup(FEB_1970, "Group2", "User2");
    insertModifiedGroup(MAR_1970, "Group1", "User1");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
      expected = ImmutableMap.<GroupPrincipal, Collection<Principal>>of();

    Checkpoint checkpoint = new Checkpoint(MAR_1970, "12Group1");
    checkModifiedGroupsPushed(LocalGroupsOnly.FALSE, checkpoint, expected,
         checkpoint);
  }

  @Test
  public void testGetGroupUpdatesSomeLdapGroups() throws Exception {
    insertUsers("User1", "User2");
    insertModifiedGroup(JAN_1970, "Group1", "User1");
    insertModifiedGroup(FEB_1970, "Group2", "User2");
    insertGroupEx(MAR_1970, "LDAP", "GroupLDAP", "User2");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of(new GroupPrincipal("Group2", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User2", "NS")),
            new GroupPrincipal("GroupLDAP", "NS"),
            ImmutableSet.of(new UserPrincipal("User2", "NS")));

    checkModifiedGroupsPushed(LocalGroupsOnly.FALSE,
        new Checkpoint(JAN_1970, "12Group1"), expected,
        new Checkpoint(MAR_1970, "12GroupLDAP"));
  }

  @Test
  public void testGetGroupUpdatesLocalGroupsOnly() throws Exception {
    insertUsers("User1", "User2");
    insertModifiedGroup(JAN_1970, "Group1", "User1");
    insertModifiedGroup(FEB_1970, "Group2", "User2");
    insertGroupEx(MAR_1970, "LDAP", "GroupLDAP", "User2");

    ImmutableMap<GroupPrincipal, ? extends Collection<? extends Principal>>
        expected = ImmutableMap.of(new GroupPrincipal("Group2", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User2", "NS")));

    checkModifiedGroupsPushed(LocalGroupsOnly.TRUE,
        new Checkpoint(JAN_1970, "12Group1"), expected,
        new Checkpoint(FEB_1970, "12Group2"));
  }

  private void testGetGroupUpdatesExceptions(Iterator<Integer> failIterations,
      DfException expectedCause,
      Map<GroupPrincipal, ? extends Collection<? extends Principal>>
      expectedGroups, Checkpoint expectedCheckpoint)
      throws DfException, IOException, InterruptedException {
    DocumentumAdaptor adaptor = getObjectUnderTestNamespaces(
        new ExceptionalResultSetTestProxies(
            "AS r_modify_date_str FROM dm_group", failIterations,
            (expectedCause != NO_EXCEPTION) ? expectedCause
            : new DfException("Recoverable exception should be handled")),
        ImmutableMap.<String, String>of());
    adaptor.modifiedGroupTraverser.setSleeper(NO_SLEEP);
    checkModifiedGroupsPushed(adaptor, Checkpoint.incremental(),
        expectedCause, expectedGroups, expectedCheckpoint);
  }

  @Test
  public void testGetGroupUpdatesFirstRowException() throws Exception {
    insertUsers("User1", "User2");
    String dateStr = getNowPlusMinutes(5);
    insertModifiedGroup(dateStr, "Group1", "User1");
    insertModifiedGroup(dateStr, "Group2", "User2");

    testGetGroupUpdatesExceptions(Iterators.singletonIterator(0),
        new DfException("Expected failure in first row"),
        ImmutableMap.<GroupPrincipal, Set<Principal>>of(),
        Checkpoint.incremental());
  }

  @Test
  public void testGetGroupUpdatesOtherRowsException() throws Exception {
    insertUsers("User0", "User1", "User2");
    String dateStr = getNowPlusMinutes(5);
    insertModifiedGroup(dateStr, "Group0", "User0");
    insertModifiedGroup(dateStr, "Group1", "User1");
    insertModifiedGroup(dateStr, "Group2", "User2");

    testGetGroupUpdatesExceptions(Iterators.cycle(2),
        NO_EXCEPTION,
        ImmutableMap.of(new GroupPrincipal("Group0", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User0", "NS")),
            new GroupPrincipal("Group1", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User1", "NS")),
            new GroupPrincipal("Group2", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User2", "NS"))),
        new Checkpoint(dateStr, "12Group2"));
  }

  @Test
  public void testGetGroupUpdatesMidGroupException() throws Exception {
    insertUsers("User0", "User1", "User2");
    String dateStr = getNowPlusMinutes(5);
    insertModifiedGroup(dateStr, "Group0", "User0");
    insertModifiedGroup(dateStr, "Group1", "User1", "User2");
    insertModifiedGroup(dateStr, "Group2", "User2");

    testGetGroupUpdatesExceptions(Iterators.forArray(2, -1),
        NO_EXCEPTION,
        ImmutableMap.of(new GroupPrincipal("Group0", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User0", "NS")),
            new GroupPrincipal("Group1", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User1", "NS"),
                new UserPrincipal("User2", "NS")),
            new GroupPrincipal("Group2", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User2", "NS"))),
        new Checkpoint(dateStr, "12Group2"));
  }

  @Test
  public void testGetGroupUpdatesPartialRowsException() throws Exception {
    insertUsers("User0", "User1", "User2");
    String dateStr = getNowPlusMinutes(5);
    insertModifiedGroup(dateStr, "Group0", "User0");
    insertModifiedGroup(dateStr, "Group1", "User1", "User2");
    insertModifiedGroup(dateStr, "Group2", "User2");

    // Fail on group transition the second time.
    testGetGroupUpdatesExceptions(Iterators.forArray(2, 2),
        new DfException("Expected Partial Rows Exception"),
        ImmutableMap.of(new GroupPrincipal("Group0", "NS_Local"),
            ImmutableSet.of(new UserPrincipal("User0", "NS"))),
        new Checkpoint(dateStr, "12Group0"));
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

  private List<Record> getModifiedDocIdsPushed(DocumentumAdaptor adaptor,
          Checkpoint checkpoint, DfException expectedCause)
          throws IOException, InterruptedException {
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    adaptor.modifiedDocumentTraverser.setCheckpoint(checkpoint);
    try {
      adaptor.getModifiedDocIds(pusher);
      assertNull("Expected an exception at " + checkpoint, expectedCause);
    } catch (IOException e) {
      if (expectedCause == NO_EXCEPTION || expectedCause != e.getCause()) {
        throw e;
      }
    }
    return pusher.getRecords();
  }

  private void checkModifiedDocIdsPushed(List<String> startPaths,
      Checkpoint checkpoint, List<Record> expectedRecords,
      Checkpoint expectedCheckpoint)
      throws DfException, IOException, InterruptedException {
    DocumentumAdaptor adaptor = getObjectUnderTest(
        ImmutableMap.of("documentum.src", Joiner.on(",").join(startPaths)));

    assertEquals(expectedRecords,
        getModifiedDocIdsPushed(adaptor, checkpoint, NO_EXCEPTION));
    assertEquals(expectedCheckpoint,
        adaptor.modifiedDocumentTraverser.getCheckpoint());
  }

  @Test
  public void testNoDocuments() throws Exception {
    String folderId = "0b01081f80001000";
    String folder = "/Folder1";
    insertFolder(JAN_1970, folderId, folder);
    Checkpoint startCheckpoint = Checkpoint.incremental();
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

    Checkpoint startCheckpoint = Checkpoint.incremental();
    checkModifiedDocIdsPushed(startPaths(folder), startCheckpoint,
        ImmutableList.<Record>of(), startCheckpoint);
  }

  @Test
  public void testModifiedDocumentsNoCheckpointObjId() throws Exception {
    String parentId = "0b001";
    String parentFolder = "/Folder1";
    insertFolder(EPOCH_1970, parentId, parentFolder);
    String folderId = "0b002";
    String folder = "/Folder1/Folder2";
    insertFolder(JAN_1970, folderId, folder);
    setParentFolderId(folderId, parentId);
    insertDocument(FEB_1970, "09001", folder + "/foo", folderId);
    insertDocument(FEB_1970, "09002", folder + "/bar", folderId);

    checkModifiedDocIdsPushed(startPaths(folder),
        new Checkpoint(JAN_1970, "0"),
        makeExpectedDocIds(folder, folder, "foo", "bar"),
        new Checkpoint(FEB_1970, "09002"));
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
    String parentId = "0b001";
    String parentFolder = "/Folder1";
    insertFolder(EPOCH_1970, parentId, parentFolder);
    String folderId = "0b002";
    String folder = "/Folder1/Folder2";
    insertFolder(FEB_1970, folderId, folder);
    setParentFolderId(folderId, parentId);

    checkModifiedDocIdsPushed(startPaths(folder),
        new Checkpoint(JAN_1970, "0b003"),
        makeExpectedDocIds(folder, folder),
        new Checkpoint(FEB_1970, folderId));
  }

  @Test
  public void testModifiedFolderNewerThanChildren() throws Exception {
    String parentId = "0b001";
    String parentFolder = "/Folder1";
    insertFolder(EPOCH_1970, parentId, parentFolder);
    String folderId = "0b002";
    String folder = "/Folder1/Folder2";
    insertFolder(MAR_1970, folderId, folder);
    setParentFolderId(folderId, parentId);
    insertDocument(JAN_1970, "09001", folder + "/foo", folderId);
    insertDocument(FEB_1970, "09002", folder + "/bar", folderId);
    insertDocument(MAR_1970, "09003", folder + "/baz", folderId);

    checkModifiedDocIdsPushed(startPaths(folder),
        new Checkpoint(JAN_1970, "09001"),
        makeExpectedDocIds(folder, "bar", "baz", folder),
        new Checkpoint(MAR_1970, "0b002"));
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
    String parentId = "0b001";
    String parentFolder = "/Folder1";
    insertFolder(EPOCH_1970, parentId, parentFolder);
    String folderId = "0b002";
    String folder = "/Folder1/Folder2";
    executeUpdate(String.format(
        "insert into dm_folder(r_object_id, r_folder_path) values('%s', '%s')",
        folderId, folder));
    insertSysObject(FEB_1970, folderId, "Folder2", folder, "dm_folder_subtype",
        parentId);
    insertDocument(FEB_1970, "09001", folder + "/foo", folderId);
    insertDocument(MAR_1970, "09002", folder + "/bar", folderId);

    checkModifiedDocIdsPushed(startPaths(folder),
        new Checkpoint(JAN_1970, folderId),
        makeExpectedDocIds(folder, "foo", folder, "bar"),
        new Checkpoint(MAR_1970, "09002"));
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

  private void testUpdateDocsExceptions(Iterator<Integer> failIterations,
      String folder, Checkpoint checkpoint, DfException expectedCause,
      List<Record> expectedRecords, Checkpoint expectedCheckpoint)
      throws Exception {
    DocumentumAdaptor adaptor =
        getObjectUnderTest(new ExceptionalResultSetTestProxies(
            "FROM dm_sysobject WHERE", failIterations,
            (expectedCause != NO_EXCEPTION) ? expectedCause
            : new DfException("Recoverable exception should be handled")),
            ImmutableMap.of("documentum.src",
                Joiner.on(",").join(startPaths(folder))));
    adaptor.modifiedDocumentTraverser.setSleeper(NO_SLEEP);
    assertEquals(expectedRecords,
        getModifiedDocIdsPushed(adaptor, checkpoint, expectedCause));
    assertEquals(expectedCheckpoint,
        adaptor.modifiedDocumentTraverser.getCheckpoint());
  }

  @Test
  public void testUpdateDocsFirstRowException()
      throws Exception {
    String folderId = "0b01081f80001000";
    String folder = "/Folder1";
    insertFolder(EPOCH_1970, folderId, folder);
    insertDocument(JAN_1970, "0901081f80001001", folder + "/foo", folderId);
    insertDocument(FEB_1970, "0901081f80001002", folder + "/bar", folderId);
    insertDocument(MAR_1970, "0901081f80001003", folder + "/baz", folderId);

    Checkpoint checkpoint = new Checkpoint(JAN_1970, "0901081f80001001");
    testUpdateDocsExceptions(Iterators.singletonIterator(0), folder, checkpoint,
        new DfException("Expected failure in first event"),
        ImmutableList.<Record>of(), checkpoint);
  }

  @Test
  public void testUpdateDocsOtherRowsException()
      throws Exception {
    String folderId = "0b01081f80001000";
    String folder = "/Folder1";
    insertFolder(EPOCH_1970, folderId, folder);
    insertDocument(JAN_1970, "0901081f80001001", folder + "/foo", folderId);
    insertDocument(FEB_1970, "0901081f80001002", folder + "/bar", folderId);
    insertDocument(MAR_1970, "0901081f80001003", folder + "/baz", folderId);

    testUpdateDocsExceptions(Iterators.cycle(1), folder,
        new Checkpoint(JAN_1970, "0901081f80001001"),
        NO_EXCEPTION,
        makeExpectedDocIds(folder, "bar", "baz"),
        new Checkpoint(MAR_1970, "0901081f80001003"));
  }

  @Test
  public void testUpdateDocsPartialRowsException()
      throws Exception {
    String folderId = "0b01081f80001000";
    String folder = "/Folder1";
    insertFolder(EPOCH_1970, folderId, folder);
    insertDocument(JAN_1970, "0901081f80001001", folder + "/foo", folderId);
    insertDocument(FEB_1970, "0901081f80001002", folder + "/bar", folderId);
    insertDocument(MAR_1970, "0901081f80001003", folder + "/baz", folderId);

    testUpdateDocsExceptions(Iterators.forArray(1, 0), folder,
        new Checkpoint(JAN_1970, "0901081f80001001"),
        new DfException("Expected Partial Rows Exception"),
        makeExpectedDocIds(folder, "bar"),
        new Checkpoint(FEB_1970, "0901081f80001002"));
  }

  private DocumentumAdaptor getObjectUnderTestDocumentTypes(String... types)
      throws DfException {
    return getObjectUnderTest(ImmutableMap.of(
        "documentum.documentTypes", Joiner.on(',').join(types)));
  }

  @Test
  public void testValidateDocumentTypes() throws DfException {
    String type1 = "dm_document";
    String type2 = "dm_document_subtype";

    DocumentumAdaptor adaptor = getObjectUnderTestDocumentTypes(type1, type2);
    assertEquals(ImmutableList.of(type1, type2),
        adaptor.getValidatedDocumentTypes());
  }

  @Test
  public void testValidateDocumentTypesSomeValid() throws DfException {
    String type1 = "dm_document_subtype";
    String type2 = "dm_my_type";
    String type3 = "dm_document";
    String type4 = "dm_folder";
    String type5 = "dm_folder_subtype";

    DocumentumAdaptor adaptor =
        getObjectUnderTestDocumentTypes(type1, type2, type3, type4, type5);
    assertEquals(ImmutableList.of(type1, type3),
        adaptor.getValidatedDocumentTypes());
  }

  @Test
  public void testValidateDocumentSysobjectSubtype() throws DfException {
    String type = "dm_sysobject_subtype";

    assertEquals(ImmutableList.of(type),
        getObjectUnderTestDocumentTypes(type).getValidatedDocumentTypes());
  }

  @Test
  public void testValidateDocumentTypesNoneValid() throws DfException {
    String type1 = "dm_some_type";
    String type2 = "dm_my_type";
    String type3 = "dm_any_type";

    DocumentumAdaptor adaptor =
        getObjectUnderTestDocumentTypes(type1, type2, type3);
    assertTrue(adaptor.getValidatedDocumentTypes().isEmpty());
  }

  @Test(expected = InvalidConfigurationException.class)
  public void testValidateDocumentTypesEmpty() throws DfException {
    getObjectUnderTestDocumentTypes("");
  }

  private void checkTypedDocIdsPushed(List<String> startPaths, String docTypes,
      Checkpoint checkpoint, List<Record> expectedRecords)
      throws DfException, IOException, InterruptedException {
    DocumentumAdaptor adaptor = getObjectUnderTest(
        ImmutableMap.of(
            "documentum.src", Joiner.on(",").join(startPaths),
            "documentum.documentTypes", docTypes));

    assertEquals(expectedRecords,
        getModifiedDocIdsPushed(adaptor, checkpoint, NO_EXCEPTION));
  }

  private void testCustomType(String docTypes, String... expect)
      throws Exception {
    String folderId = "0b001";
    String folder = "/Folder1";
    insertFolder(JAN_1970, folderId, folder);
    insertSysObject(MAR_1970, "09001", "foo", folder + "/foo",
        "dm_document", folderId);
    insertSysObject(MAR_1970, "09002", "bar", folder + "/bar",
        "dm_document_subtype", folderId);
    insertSysObject(MAR_1970, "09003", "baz", folder + "/baz",
        "dm_sysobject_subtype", folderId);

    checkTypedDocIdsPushed(startPaths(folder),
        docTypes,
        new Checkpoint(FEB_1970, folder),
        makeExpectedDocIds(folder, expect));
  }

  @Test
  public void testCustomType_all() throws Exception {
    testCustomType("dm_document, dm_document_subtype, dm_sysobject_subtype",
        "foo", "bar", "baz");
  }

  @Test
  public void testCustomType_skip() throws Exception {
    testCustomType("dm_document, dm_document_subtype", "foo", "bar");
  }

  @Test
  public void testCustomType_NonSysobject() throws Exception {
    String folderId = "0b001";
    String folder = "/Folder1";
    insertFolder(JAN_1970, folderId, folder);
    insertSysObject(MAR_1970, "09001", "foo", folder + "/foo",
        "dm_document", folderId);
    insertSysObject(MAR_1970, "09002", "bar", folder + "/bar",
        "dm_store", folderId);

    checkTypedDocIdsPushed(startPaths(folder),
        "dm_document, dm_store",
        new Checkpoint(FEB_1970, folder),
        makeExpectedDocIds(folder, "foo"));
  }
}
