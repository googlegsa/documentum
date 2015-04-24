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
import com.google.enterprise.adaptor.Acl;
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.GroupPrincipal;
import com.google.enterprise.adaptor.Principal;
import com.google.enterprise.adaptor.UserPrincipal;

import com.documentum.com.IDfClientX;
import com.documentum.fc.client.IDfACL;
import com.documentum.fc.client.IDfCollection;
import com.documentum.fc.client.IDfGroup;
import com.documentum.fc.client.IDfPermitType;
import com.documentum.fc.client.IDfQuery;
import com.documentum.fc.client.IDfSession;
import com.documentum.fc.client.IDfUser;
import com.documentum.fc.common.DfException;
import com.documentum.fc.common.DfId;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

/**
 * Returns all Documentum ACLs in map with doc id as key and Acl as value.
 */
public class DocumentumAcls {
  private static Logger logger =
      Logger.getLogger(DocumentumAcls.class.getName());

  private final IDfClientX dmClientX;
  private final IDfSession dmSession;
  private final String localNamespace;
  private final String globalNamespace;
  private final String windowsDomain;

  DocumentumAcls(IDfClientX dmClientX, IDfSession dmSession,
      String localNamespace, String globalNamespace, String windowsDomain) {
    Preconditions.checkNotNull(dmClientX, "dmClientX may not be null");
    Preconditions.checkNotNull(dmSession, "dmSession may not be null");
    Preconditions.checkNotNull(localNamespace,
        "localNamespace may not be null");
    Preconditions.checkNotNull(globalNamespace,
        "globalNamespace may not be null");
    Preconditions.checkNotNull(windowsDomain, "windowsDomain may not be null");
    this.dmClientX = dmClientX;
    this.dmSession = dmSession;
    this.localNamespace = localNamespace;
    this.globalNamespace = globalNamespace;
    this.windowsDomain = windowsDomain;
  }

  private IDfQuery makeAclQuery() {
    IDfQuery query = dmClientX.getQuery();
    query.setDQL("select r_object_id from dm_acl order by r_object_id");
    return query;
  }

  /**
   * Returns all Documentum ACLs in map with doc id and Acl.
   * 
   * In Documentum, ACLs are high level objects separate from content objects.
   * An ACL can be applied to one or many content objects. Or, each object 
   * can have it's own individual ACL applied to it. So need to send all 
   * the ACLs in Documentum to GSA.
   * 
   * @return Documentum ACLs in map
   * @throws DfException if error in getting ACL information.
   */
  public Map<DocId, Acl> getAcls() throws DfException {
    IDfQuery query = makeAclQuery();
    IDfCollection dmAclCollection =
        query.execute(dmSession, IDfQuery.DF_EXECREAD_QUERY);
    try {
      Map<DocId, Acl> aclMap = new HashMap<DocId, Acl>();
      while (dmAclCollection.next()) {
        String objId = dmAclCollection.getString("r_object_id");
        IDfACL dmAclObj = (IDfACL) dmSession.getObject(new DfId(objId));
        Acl acl = processAcl(dmAclObj);
        aclMap.put(new DocId(objId), acl);
      }
      return aclMap;
    } finally {
      try {
        dmAclCollection.close();
      } catch (DfException e) {
        logger.log(Level.WARNING, "Error closing collection", e);
      }
    }
  }

  /**
   * Processes users and groups from the ACL object, populates permits set with
   * users and groups with READ permission. Populates denies set with users and
   * groups with no READ permission.
   * 
   * @param dmAclObj ACL object to be processed.
   * @return Adaptor Acl object.
   * @throws DfException if error in getting user or group information.
   */
  private Acl processAcl(IDfACL dmAclObj) throws DfException {
    Set<Principal> permits = new HashSet<Principal>();
    Set<Principal> denies = new HashSet<Principal>();

    for (int i = 0; i < dmAclObj.getAccessorCount(); i++) {
      String accessorName = dmAclObj.getAccessorName(i);
      int permitType = dmAclObj.getAccessorPermitType(i);
      String principalName = getPrincipalName(accessorName);
      if (principalName == null) {
        continue;
      }
      if (permitType == IDfPermitType.ACCESS_RESTRICTION) {
        if (dmAclObj.getAccessorPermit(i) <= IDfACL.DF_PERMIT_READ) {
          denies.add(getPrincipal(accessorName, principalName,
              dmAclObj.isGroup(i)));
        }
      } else if (permitType == IDfPermitType.ACCESS_PERMIT) {
        if (dmAclObj.getAccessorPermit(i) >= IDfACL.DF_PERMIT_READ) {
          if (accessorName.equalsIgnoreCase("dm_owner")
              || accessorName.equalsIgnoreCase("dm_group")) {
            // skip dm_owner and dm_group for now.
            // TODO (Srinivas): Need to resolve these acls for
            //      both allow and deny.
            continue;
          } else {
            permits.add(getPrincipal(accessorName, principalName,
                dmAclObj.isGroup(i)));
          }
        }
      }
    }

    return new Acl.Builder().setPermits(permits).setDenies(denies)
        .setInheritanceType(Acl.InheritanceType.PARENT_OVERRIDES)
        .setEverythingCaseSensitive().build();
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
  private Principal getPrincipal(String accessorName, String principalName,
      boolean isGroup) throws DfException {
    Principal principal;
    if (accessorName.equalsIgnoreCase("dm_world") || isGroup) {
      principal =
          new GroupPrincipal(principalName, getGroupNamespace(accessorName));
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
  private String getPrincipalName(String accessorName) throws DfException {
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

    if (!Strings.isNullOrEmpty(userObj.getUserSourceAsString())
        && userObj.getUserSourceAsString().equalsIgnoreCase("ldap")) {
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
   * @throws InvalidNameException if the input is invalid
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
    // special group local to repository
    if (groupName.equalsIgnoreCase("dm_world")) {
      return localNamespace;
    }

    IDfGroup groupObj = (IDfGroup) dmSession.getObjectByQualification(
        "dm_group where group_name = '" + singleQuoteEscapeString(groupName)
        + "'");
    if (groupObj == null) {
      return null;
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
