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

import static java.util.Collections.singletonList;

import com.google.common.base.Preconditions;
import com.google.enterprise.adaptor.Acl;
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.Principal;

import com.documentum.com.IDfClientX;
import com.documentum.fc.client.IDfACL;
import com.documentum.fc.client.IDfCollection;
import com.documentum.fc.client.IDfPermitType;
import com.documentum.fc.client.IDfQuery;
import com.documentum.fc.client.IDfSession;
import com.documentum.fc.common.DfException;
import com.documentum.fc.common.DfId;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Returns all Documentum ACLs in map with doc id as key and Acl as value.
 *
 * Documentum ACLs are modeled as a chain of between 1 and N + 2 GSA
 * ACLs, one ACL for each required group (N, where N >= 0), one for
 * the required group set (0 or 1), and one for the basic permit and
 * restricted permissions (1).
 */
class DocumentumAcls {
  private static Logger logger =
      Logger.getLogger(DocumentumAcls.class.getName());

  private final IDfClientX dmClientX;
  private final IDfSession dmSession;
  private final Principals principals;

  DocumentumAcls(IDfClientX dmClientX, IDfSession dmSession,
      Principals principals) {
    Preconditions.checkNotNull(dmClientX, "dmClientX may not be null");
    Preconditions.checkNotNull(dmSession, "dmSession may not be null");
    Preconditions.checkNotNull(principals, "principals may not be null");
    this.dmClientX = dmClientX;
    this.dmSession = dmSession;
    this.principals = principals;
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
   * can have its own individual ACL applied to it. So need to send all
   * the ACLs in Documentum to GSA.
   * 
   * @return a map of Adaptor Acls for all Documentum ACLs
   * @throws DfException if error in getting ACL information.
   */
  public Map<DocId, Acl> getAcls() throws DfException {
    IDfQuery query = makeAclQuery();
    IDfCollection dmAclCollection =
        query.execute(dmSession, IDfQuery.DF_EXECREAD_QUERY);
    try {
      Map<DocId, Acl> aclMap = new HashMap<DocId, Acl>();
      while (dmAclCollection.next()) {
        String objectId = dmAclCollection.getString("r_object_id");
        IDfACL dmAcl = (IDfACL) dmSession.getObject(new DfId(objectId));
        Acl.Builder basicAclBuilder = getBasicAcl(dmAcl);

        if (isRequiredGroupOrSet(dmAcl)) {
          logger.log(Level.FINE,
              "ACL {0} has required groups or required group set", objectId);
          String parentAclId =
              addRequiredGroupOrSetAclsToMap(dmAcl, objectId, aclMap);
          basicAclBuilder.setInheritFrom(new DocId(parentAclId));
        }

        aclMap.put(new DocId(objectId), basicAclBuilder.build());
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
   * Returns true if Acl permit type is required group or required group set.
   *
   * @param dmAcl Documentum ACL object.
   * @return true if Acl permit type is required group or required group set.
   * @throws DfException if error in getting accessor info.
   */
  private boolean isRequiredGroupOrSet(IDfACL dmAcl) throws DfException {
    for (int i = 0; i < dmAcl.getAccessorCount(); i++) {
      int permitType = dmAcl.getAccessorPermitType(i);
      if (permitType == IDfPermitType.REQUIRED_GROUP
          || permitType == IDfPermitType.REQUIRED_GROUP_SET) {
        return true;
      }
    }
    return false;
  }

  /**
   * Populates the map with doc id and Acl for a Documentum ACL with
   * required groups or required group sets.
   *
   * @param dmAcl Documentum ACL object.
   * @param objectId Documentum ACL object id.
   * @param aclMap Map with doc id and acl.
   * @return the doc ID of the first Adaptor Acl in the chain, which
   *     the basic Acl will inherit from
   * @throws DfException if error in getting acl info.
   */
  private String addRequiredGroupOrSetAclsToMap(IDfACL dmAcl,
      String objectId, Map<DocId, Acl> aclMap) throws DfException {
    List<String> requiredGroupSet = new ArrayList<String>();
    String parentAclId = null;
    for (int i = 0; i < dmAcl.getAccessorCount(); i++) {
      String accessorName = dmAcl.getAccessorName(i);
      int permitType = dmAcl.getAccessorPermitType(i);
      if (permitType == IDfPermitType.REQUIRED_GROUP) {
        String aclId = objectId + "_" + accessorName;
        Acl acl = getRequiredAcl(parentAclId, singletonList(accessorName));
        aclMap.put(new DocId(aclId), acl);
        parentAclId = aclId;
      } else if (permitType == IDfPermitType.REQUIRED_GROUP_SET) {
        requiredGroupSet.add(accessorName);
      }
    }

    if (!requiredGroupSet.isEmpty()) {
      String aclId = objectId + "_reqGroupSet";
      Acl acl = getRequiredAcl(parentAclId, requiredGroupSet);
      aclMap.put(new DocId(aclId), acl);
      parentAclId = aclId;
    }

    return parentAclId;
  }

  /**
   * Creates an Adaptor Acl object with required groups or required group sets.
   *
   * @param parentAclId the doc ID of the parent ACL in the chain
   * @param groups the group names
   * @return Adaptor Acl object.
   * @throws DfException if error in getting acl info.
   */
  private Acl getRequiredAcl(String parentAclId, List<String> groups)
      throws DfException {
    Set<Principal> permits = new HashSet<Principal>();
    for (String name : groups) {
      permits.add(principals.getPrincipal(name, name, true));
    }
    Acl.Builder builder = new Acl.Builder();
    builder.setPermits(permits);
    builder.setInheritanceType(Acl.InheritanceType.AND_BOTH_PERMIT);
    if (parentAclId != null) {
      builder.setInheritFrom(new DocId(parentAclId));
    }
    return builder.build();
  }

  /**
   * Creates an Adaptor Acl.Builder for the basic permissions in the
   * ACL object. Populates permits set with users and groups with READ
   * permission. Populates denies set with users and groups with no
   * READ permission.
   * 
   * @param dmAcl Documentum ACL object to be processed.
   * @return Adaptor Acl.Builder object.
   * @throws DfException if error in getting user or group information.
   */
  private Acl.Builder getBasicAcl(IDfACL dmAcl) throws DfException {
    Set<Principal> permits = new HashSet<Principal>();
    Set<Principal> denies = new HashSet<Principal>();

    for (int i = 0; i < dmAcl.getAccessorCount(); i++) {
      String accessorName = dmAcl.getAccessorName(i);
      int permitType = dmAcl.getAccessorPermitType(i);
      String principalName = principals.getPrincipalName(accessorName);
      if (principalName == null) {
        continue;
      }
      if (permitType == IDfPermitType.ACCESS_RESTRICTION) {
        if (dmAcl.getAccessorPermit(i) <= IDfACL.DF_PERMIT_READ) {
          denies.add(principals.getPrincipal(accessorName, principalName,
              dmAcl.isGroup(i)));
        }
      } else if (permitType == IDfPermitType.ACCESS_PERMIT) {
        if (dmAcl.getAccessorPermit(i) >= IDfACL.DF_PERMIT_READ) {
          if (accessorName.equalsIgnoreCase("dm_owner")
              || accessorName.equalsIgnoreCase("dm_group")) {
            // skip dm_owner and dm_group for now.
            // TODO (Srinivas): Need to resolve these acls for
            //      both allow and deny.
            continue;
          } else {
            permits.add(principals.getPrincipal(accessorName, principalName,
                dmAcl.isGroup(i)));
          }
        }
      }
    }

    return new Acl.Builder().setPermits(permits).setDenies(denies)
        .setEverythingCaseSensitive()
        .setInheritanceType(Acl.InheritanceType.PARENT_OVERRIDES);
  }
}
