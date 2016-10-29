// Copyright 2016 Google Inc. All Rights Reserved.
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import com.documentum.fc.client.IDfSession;
import com.documentum.fc.client.IDfUser;
import com.documentum.fc.client.impl.typeddata.NoSuchAttributeException;
import com.documentum.fc.common.DfException;
import org.junit.Before;
import org.junit.Test;

/** Unit tests for the Principals utility class. */
public class PrincipalsTest {
  private IDfSession session;

  @Before
  public void setUp() {
    Principals.clearCache();
    session = Proxies.newProxyInstance(IDfSession.class, new SessionMock());
  }

  @Test
  public void testGetPrincipal_builtin() throws DfException {
    Principals principals = new Principals(session, "local", "global", null);
    assertEquals("dm_world",
        principals.getPrincipal("dm_world", true).getName());
  }

  @Test
  public void testGetPrincipal_missing() throws DfException {
    Principals principals = new Principals(session, "local", "global", null);
    assertNull(principals.getPrincipal("nobody", false));
  }

  @Test
  public void testGetPrincipal_exception() throws DfException {
    Principals principals = new Principals(session, "local", "global", null);
    assertNull(principals.getPrincipal("exception", false));
  }

  @Test
  public void testGetPrincipal_dnDomain() throws DfException {
    Principals principals = new Principals(session, "local", "global", null);
    assertEquals("example\\janedoe",
        principals.getPrincipal("user:janedoe:ldap:dc=example,dc=com:", false)
        .getName());
  }

  @Test
  public void testGetPrincipal_dnInvalid() throws DfException {
    Principals principals = new Principals(session, "local", "global", null);
    assertNull(
        principals.getPrincipal("user:janedoe:ldap:is this a DN?:", false));
  }

  @Test
  public void testGetPrincipal_dnEmpty_windowsNull() throws DfException {
    Principals principals = new Principals(session, "local", "global", null);
    assertEquals("janedoe",
        principals.getPrincipal("user:janedoe:ldap::", false).getName());
  }

  @Test
  public void testGetPrincipal_dnEmpty_windowsDomain() throws DfException {
    Principals principals =
        new Principals(session, "local", "global", "example");
    assertEquals("example\\janedoe",
        principals.getPrincipal("user:janedoe:ldap::", false).getName());
  }

  @Test
  public void testGetPrincipal_dnNoDomain_windowsNull() throws DfException {
    Principals principals = new Principals(session, "local", "global", null);
    assertEquals("janedoe",
        principals.getPrincipal("user:janedoe:ldap:cn=Jane Doe,ou=eng:", false)
        .getName());
  }

  @Test
  public void testGetPrincipal_dnNoDomain_windowsDomain()
      throws DfException {
    Principals principals =
        new Principals(session, "local", "global", "example");
    assertEquals("example\\janedoe",
        principals.getPrincipal("user:janedoe:ldap:cn=Jane Doe,ou=eng:", false)
        .getName());
  }

  private static class SessionMock {
    public Object getObjectByQualification(String query) throws DfException {
      if (query.contains("user:")) {
        return Proxies.newProxyInstance(IDfUser.class, new UserMock(query));
      } else if (query.contains("exception")) {
        throw new NoSuchAttributeException("somefield");
      } else {
        return null;
      }
    }
  }

  private static class UserMock {
    private final String loginName;
    private final String source;
    private final String ldapDn;

    public UserMock(String query) {
      String[] pieces = query.split(":");
      assertEquals(query, 5, pieces.length);
      loginName = pieces[1];
      source = pieces[2];
      ldapDn = pieces[3];
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
      return false;
    }
  }
}
