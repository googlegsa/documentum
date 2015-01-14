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

import static org.junit.Assert.*;

import com.google.common.collect.ImmutableSet;
import com.google.enterprise.adaptor.AdaptorContext;
import com.google.enterprise.adaptor.Config;

import com.documentum.com.IDfClientX;
import com.documentum.fc.client.DfAuthenticationException;
import com.documentum.fc.client.DfIdentityException;
import com.documentum.fc.client.DfPrincipalException;
import com.documentum.fc.client.DfServiceException;
import com.documentum.fc.client.IDfClient;
import com.documentum.fc.client.IDfSession;
import com.documentum.fc.client.IDfSessionManager;
import com.documentum.fc.common.DfException;
import com.documentum.fc.common.IDfLoginInfo;

import org.junit.Test;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class DocumentumAdaptorTest {

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

    adaptor.init(context);

    assertEquals("testuser", proxyCls.username);
    assertEquals("testpwd", proxyCls.password);
    assertEquals("testdocbase", proxyCls.docbaseName);
    assertEquals(1, proxyCls.docbaseLoginInfoMap.size());
    assertEquals(1, proxyCls.docbaseSessionMap.size());

    List<String> expectedMethodCallSequence = Arrays.asList(
        "getLocalClient", "newSessionManager",
        "getLoginInfo", "setIdentity",
        "getSession", "release"
    );
    assertEquals(expectedMethodCallSequence, proxyCls.methodCallSequence);

    Set<String> expectedMethodCallSet =
        ImmutableSet.of("setUser", "setPassword", "getDFCVersion",
            "getServerVersion");
    assertEquals(expectedMethodCallSet, proxyCls.methodCalls);
  }

  private class InitTestProxies {
    List <String> methodCallSequence = new ArrayList<String>();
    Set <String> methodCalls = new HashSet<String>();

    IDfClient client = getProxyClient();
    IDfLoginInfo loginInfo = getProxyLoginInfo();

    Map<String, IDfLoginInfo> docbaseLoginInfoMap =
        new HashMap<String, IDfLoginInfo>();
    Map<String, IDfSession> docbaseSessionMap =
        new HashMap<String, IDfSession>();

    IDfSessionManager sessionManager = getProxySessionManager();

    String username;
    String password;
    String docbaseName;

    public IDfClientX getProxyClientX() {
      return (IDfClientX) Proxy.newProxyInstance(
          IDfClientX.class.getClassLoader(), new Class<?>[] {IDfClientX.class},
          new ClientXHandler());
    }

    private class ClientXHandler implements InvocationHandler {
      public Object invoke(Object proxy, Method method, Object[] args)
          throws DfException {

        if ("getDFCVersion".equals(method.getName())) {
          methodCalls.add(method.getName());
          return "1.0.0.000 (Mock DFC)";
        } else if ("getLocalClient".equals(method.getName())) {
          methodCallSequence.add(method.getName());
          return client;
        } else if ("getLoginInfo".equals(method.getName())) {
          methodCallSequence.add(method.getName());
          return loginInfo;
        }
        throw new AssertionError("invalid method: " + method.getName());
      }
    }

    public IDfClient getProxyClient() {
      return (IDfClient) Proxy.newProxyInstance(
          IDfClient.class.getClassLoader(), new Class<?>[] {IDfClient.class},
          new ClientHandler());
    }

    private class ClientHandler implements InvocationHandler {
      public Object invoke(Object proxy, Method method, Object[] args)
          throws DfException {
        methodCallSequence.add(method.getName());

        if ("newSessionManager".equals(method.getName())) {
          return sessionManager;
        }
        throw new AssertionError("invalid method: " + method.getName());
      }
    }

    public IDfLoginInfo getProxyLoginInfo() {
      return (IDfLoginInfo) Proxy.newProxyInstance(
          IDfLoginInfo.class.getClassLoader(),
          new Class<?>[] {IDfLoginInfo.class}, new LoginInfoHandler());
    }

    private class LoginInfoHandler implements InvocationHandler {
      public Object invoke(Object proxy, Method method, Object[] args) {
        methodCalls.add(method.getName());

        if ("setPassword".equals(method.getName())) {
          password = (String) args[0];
          return null;
        } else if ("setUser".equals(method.getName())) {
          username = (String) args[0];
          return null;
        }
        throw new AssertionError("invalid method: " + method.getName());
      }
    }

    public IDfSessionManager getProxySessionManager() {
      return (IDfSessionManager) Proxy.newProxyInstance(
          IDfSessionManager.class.getClassLoader(),
          new Class<?>[] {IDfSessionManager.class},
          new SessionManagerHandler());
    }

    private class SessionManagerHandler implements
        InvocationHandler {
      public Object invoke(Object proxy, Method method, Object[] args)
          throws DfIdentityException, DfAuthenticationException,
          DfPrincipalException, DfServiceException {
        methodCallSequence.add(method.getName());

        if ("getSession".equals(method.getName())) {
          String docbaseName = (String) args[0];
          IDfSession session = docbaseSessionMap.get(docbaseName);
          if (session == null) {
            session = getProxySession();
            docbaseSessionMap.put(docbaseName, session);
          }
          return session;
        } else if ("release".equals(method.getName())) {
          // TODO (sveldurthi): remove from the map to release the session
          return null;
        } else if ("setIdentity".equals(method.getName())) {
          docbaseName = (String) args[0];
          IDfLoginInfo loginInfo = (IDfLoginInfo) args[1];
          docbaseLoginInfoMap.put(docbaseName, loginInfo);
          return null;
        }
        throw new AssertionError("invalid method: " + method.getName());
      }
    }

    public IDfSession getProxySession() {
      return (IDfSession) Proxy.newProxyInstance(
          IDfSession.class.getClassLoader(), new Class<?>[] {IDfSession.class},
          new SessionHandler());
    }

    private class SessionHandler implements InvocationHandler {
      public Object invoke(Object proxy, Method method, Object[] args)
          throws DfException {
        methodCalls.add(method.getName());

        if ("getServerVersion".equals(method.getName())) {
          return "1.0.0.000 (Mock CS)";
        }
        throw new AssertionError("invalid method: " + method.getName());
      }
    }
  }
}
