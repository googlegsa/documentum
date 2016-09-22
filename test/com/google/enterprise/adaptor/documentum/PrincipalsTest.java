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
    session = Proxies.newProxyInstance(IDfSession.class, new SessionMock());
  }

  // TODO(jlacey): Change these tests to use getPrincipal() now that
  // getPrincipalName() is only @VisibleForTesting.

  @Test
  public void testGetPrincipalName_builtin() throws DfException {
    Principals principals = new Principals(session, "local", "global", null);
    assertEquals("dm_world", principals.getPrincipalName("dm_world"));
  }

  @Test
  public void testGetPrincipalName_missing() throws DfException {
    Principals principals = new Principals(session, "local", "global", null);
    assertNull(principals.getPrincipalName("nobody"));
  }

  @Test
  public void testGetPrincipalName_exception() throws DfException {
    Principals principals = new Principals(session, "local", "global", null);
    assertNull(principals.getPrincipalName("exception"));
  }

  @Test
  public void testGetPrincipalName_dnDomain() throws DfException {
    Principals principals = new Principals(session, "local", "global", null);
    assertEquals("example\\janedoe",
        principals.getPrincipalName("user:janedoe:ldap:dc=example,dc=com:"));
  }

  @Test
  public void testGetPrincipalName_dnInvalid() throws DfException {
    Principals principals = new Principals(session, "local", "global", null);
    assertNull(principals.getPrincipalName("user:janedoe:ldap:is this a DN?:"));
  }

  @Test
  public void testGetPrincipalName_dnEmpty_windowsNull() throws DfException {
    Principals principals = new Principals(session, "local", "global", null);
    assertEquals("janedoe", principals.getPrincipalName("user:janedoe:ldap::"));
  }

  @Test
  public void testGetPrincipalName_dnEmpty_windowsDomain() throws DfException {
    Principals principals =
        new Principals(session, "local", "global", "example");
    assertEquals("example\\janedoe",
        principals.getPrincipalName("user:janedoe:ldap::"));
  }

  @Test
  public void testGetPrincipalName_dnNoDomain_windowsNull() throws DfException {
    Principals principals = new Principals(session, "local", "global", null);
    assertEquals("janedoe",
        principals.getPrincipalName("user:janedoe:ldap:cn=Jane Doe,ou=eng:"));
  }

  @Test
  public void testGetPrincipalName_dnNoDomain_windowsDomain()
      throws DfException {
    Principals principals =
        new Principals(session, "local", "global", "example");
    assertEquals("example\\janedoe",
        principals.getPrincipalName("user:janedoe:ldap:cn=Jane Doe,ou=eng:"));
  }

  private class SessionMock {
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

  private class UserMock {
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
