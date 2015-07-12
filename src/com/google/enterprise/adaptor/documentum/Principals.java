// Copyright 2015 Google Inc. All Rights Reserved.
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

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.enterprise.adaptor.GroupPrincipal;
import com.google.enterprise.adaptor.Principal;
import com.google.enterprise.adaptor.UserPrincipal;

import com.documentum.fc.client.IDfGroup;
import com.documentum.fc.client.IDfSession;
import com.documentum.fc.client.IDfUser;
import com.documentum.fc.common.DfException;

import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

/**
 * Generates Principals for Documentum Users and Groups.
 */
class Principals {
  private static Logger logger = Logger.getLogger(Principals.class.getName());

  private final IDfSession dmSession;
  private final String localNamespace;
  private final String globalNamespace;
  private final String windowsDomain;

  Principals(IDfSession dmSession,
      String localNamespace, String globalNamespace, String windowsDomain) {
    Preconditions.checkNotNull(dmSession, "dmSession may not be null");
    Preconditions.checkNotNull(localNamespace,
        "localNamespace may not be null");
    Preconditions.checkNotNull(globalNamespace,
        "globalNamespace may not be null");
    this.dmSession = dmSession;
    this.localNamespace = localNamespace;
    this.globalNamespace = globalNamespace;
    this.windowsDomain = windowsDomain;
  }

  /**
   * Return principal for user or group.
   * 
   * @param accessorName accessor for the user or group.
   * @param principalName principal name for the user or group.
   * @param isGroup true if group.
   * @return
   * @throws DfException if error in getting group name space.
   */
  public Principal getPrincipal(String accessorName, String principalName,
      boolean isGroup) throws DfException {
    Principal principal;
    // special group local to repository
    if (accessorName.equalsIgnoreCase("dm_world")) {
      principal = new GroupPrincipal(principalName, localNamespace);
    } else if (isGroup) {
      String namespace = getGroupNamespace(accessorName);
      principal = new GroupPrincipal(principalName, namespace);
    } else {
      principal = new UserPrincipal(principalName, globalNamespace);
    }
    return principal;
  }

  /**
   * Return principal name, login name decorated with domain, for the given
   * user or group.
   *
   * @param accessorName accessor (user or group) name.
   * @throws DfException if error in getting user information.
   */
  public String getPrincipalName(String accessorName) throws DfException {
    if (accessorName.equalsIgnoreCase("dm_world")
        || accessorName.equalsIgnoreCase("dm_owner")
        || accessorName.equalsIgnoreCase("dm_group")) {
      return accessorName;
    }

    IDfUser userObj = (IDfUser) dmSession.getObjectByQualification(
        "dm_user where user_name = '" + singleQuoteEscapeString(accessorName)
        + "'");
    if (userObj == null) {
      return null;
    }

    if ("ldap".equalsIgnoreCase(userObj.getUserSourceAsString())) {
      String dnName = userObj.getUserDistinguishedLDAPName();
      if (Strings.isNullOrEmpty(dnName)) {
        // TODO(jlacey): This is inconsistent with authN, which
        // matches such users against windows_domain. This case
        // probably can't happen, so I don't think it's important.
        logger.log(Level.FINE, "Missing DN for user: {0}", accessorName);
        return null;
      }

      try {
        LdapName dnDomain = getDomainComponents(dnName);
        if (!dnDomain.isEmpty()) {
          return getFirstDomainFromDN(dnDomain) + "\\"
              + userObj.getUserLoginName();
        }
        // Else fall-through to use windows_domain.
      } catch (InvalidNameException e) {
        logger.log(Level.FINE,
            "Invalid DN " + dnName + " for user: " + accessorName, e);
        return null;
      }
    }

    String principalName;
    if (!Strings.isNullOrEmpty(windowsDomain) && !userObj.isGroup()) {
      logger.log(Level.FINEST,
          "using configured domain: {0} for unsynchronized user {1}",
          new String[] {windowsDomain, accessorName});
      principalName = windowsDomain + "\\" + userObj.getUserLoginName();
    } else {
      principalName = userObj.getUserLoginName();
    }
    return principalName;
  }

  /**
   * Extracts the DC attributes in a DN string as an {@code LdapName}.
   *
   * @param userDn the Documentum user LDAP DN
   * @return LDAP name for the given user DN
   * @throws InvalidNameException if a syntax violation is detected.
   */
  public static LdapName getDomainComponents(String userDn)
      throws InvalidNameException{
    LdapName userName = new LdapName(userDn);
    ArrayList<Rdn> userDnDomain = new ArrayList<Rdn>(userName.size());
    for (Rdn rdn : userName.getRdns()) {
      if (rdn.getType().equalsIgnoreCase("dc")) {
        userDnDomain.add(rdn);
      }
    }
    return new LdapName(userDnDomain);
  }

  /**
   * Gets the leftmost DC from an {@code LdapName} of DC RDNs.
   * For example, given
   * <pre>
   * new LdapName("uid=xyz,ou=engineer,dc=corp.example,dc=com")
   * </pre>
   * it will return "corp".
   *
   * @param domain the domain name
   * @return the first domain component, or {@code null} if the DN
   *     does not contain a DC attribute
   */
  public static String getFirstDomainFromDN(LdapName domain) {
    if (domain.isEmpty()) {
      return null;
    } else {
      // RDNs are numbered right-to-left.
      return domain.getRdn(domain.size() - 1).getValue().toString();
    }
  }

  /**
   * Returns group name space for the given group.
   *
   * @param groupName group name.
   * @throws DfException if error in getting group information.
   */
  private String getGroupNamespace(String groupName) throws DfException {
    IDfGroup groupObj = (IDfGroup) dmSession.getObjectByQualification(
        "dm_group where group_name = '" + singleQuoteEscapeString(groupName)
        + "'");
    if (groupObj == null) {
      // An ACL or Group contains a non-existent group?
      // Group lookup will not return such a group, and with it in
      // the local namespace, neither should anyone else.
      return localNamespace;
    } else if (Strings.isNullOrEmpty(groupObj.getGroupSource())) {
      logger.log(Level.FINER, "local namespace for group {0}", groupName);
      return localNamespace;
    } else {
      logger.log(Level.FINER, "global namespace for group {0}", groupName);
      return globalNamespace;
    }
  }

  /**
   * Returns the string with single quote escaped, for use in DQL.
   *
   * @param value string value.
   * @return single quote escaped string.
   */
  private String singleQuoteEscapeString(String value) {
    return value.replace("'", "''");
  }
}
