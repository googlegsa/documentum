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
        if (isRequiredGroupOrSet(dmAclObj)) {
          logger.log(Level.FINE,
              "ACL {0} has required groups or required group set", objId);
          addSecureAclWithRequiredGroupOrSetToAclMap(dmAclObj, objId, aclMap);
        } else {
          Acl acl = processAcl(dmAclObj)
              .setInheritanceType(Acl.InheritanceType.PARENT_OVERRIDES).build();
          aclMap.put(new DocId(objId), acl);
        }
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
   * @param aclObj Documentum ACL object.
   * @return true if Acl permit type is required group or required group set.
   * @throws DfException if error in getting accessor info.
   */
  private boolean isRequiredGroupOrSet(IDfACL aclObj) throws DfException {
    for (int i = 0; i < aclObj.getAccessorCount(); i++) {
      int permitType = aclObj.getAccessorPermitType(i);
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
   * @param aclObj Documentum ACL object.
   * @param objId Documentum ACL object id.
   * @param aclMap Map with doc id and acl.
   * @throws DfException if error in getting acl info.
   */
  private void addSecureAclWithRequiredGroupOrSetToAclMap(IDfACL aclObj,
      String objId, Map<DocId, Acl> aclMap) throws DfException {
    List<String> requiredGroupSetPrincipals = new ArrayList<String>();
    String accessor = null;
    String parentIdValue = null;
    for (int i = 0; i < aclObj.getAccessorCount(); i++) {
      int permitType = aclObj.getAccessorPermitType(i);
      if (permitType == IDfPermitType.REQUIRED_GROUP) {
        accessor = aclObj.getAccessorName(i);
        String aclIdValue = objId + "_" + accessor;
        // do not process ACL principals
        Acl acl =
            getRequiredSecureAcl(null, aclIdValue, parentIdValue, accessor);
        aclMap.put(new DocId(aclIdValue), acl);
        parentIdValue = aclIdValue;
      } else if (permitType == IDfPermitType.REQUIRED_GROUP_SET) {
        String accessorName = aclObj.getAccessorName(i);
        requiredGroupSetPrincipals.add(accessorName);
      }
    }

    if (!requiredGroupSetPrincipals.isEmpty()) {
      String idValue = objId + "_reqGroupSet";
      String[] groups = requiredGroupSetPrincipals.toArray(new String[0]);
      Acl acl = getRequiredSecureAcl(null, idValue, parentIdValue, groups);
      aclMap.put(new DocId(idValue), acl);
      parentIdValue = idValue;
    }
    Acl acl = getRequiredSecureAcl(aclObj, objId, parentIdValue);
    aclMap.put(new DocId(objId), acl);
  }

  /**
   * Creates an Adaptor Acl object with required groups or required group sets.
   *
   * @param aclObj Documentum ACL object.
   * @param idValue id value of acl in acl chain.
   * @param parentIdValue parent id value of acl in acl chain.
   * @param group group names.
   * @return Adaptor Acl object.
   * @throws DfException if error in getting acl info.
   */
  private Acl getRequiredSecureAcl(IDfACL aclObj, String idValue,
      String parentIdValue, String... group) throws DfException {
    Set<Principal> permits = new HashSet<Principal>();
    Acl.Builder builder;

    if (aclObj != null) {
      builder = processAcl(aclObj);
      builder.setInheritanceType(Acl.InheritanceType.PARENT_OVERRIDES);
    } else {
      builder = new Acl.Builder();
      for (String name : group) {
        permits.add(principals.getPrincipal(name, name, true));
      }
      builder.setPermits(permits);
      builder.setInheritanceType(Acl.InheritanceType.AND_BOTH_PERMIT);
    }

    if (parentIdValue != null) {
      builder.setInheritFrom(new DocId(parentIdValue));
    }

    return builder.build();
  }

  /**
   * Processes users and groups from the ACL object, populates permits set with
   * users and groups with READ permission. Populates denies set with users and
   * groups with no READ permission.
   * 
   * @param dmAclObj ACL object to be processed.
   * @return Adaptor Acl.Builder object.
   * @throws DfException if error in getting user or group information.
   */
  private Acl.Builder processAcl(IDfACL dmAclObj) throws DfException {
    Set<Principal> permits = new HashSet<Principal>();
    Set<Principal> denies = new HashSet<Principal>();

    for (int i = 0; i < dmAclObj.getAccessorCount(); i++) {
      String accessorName = dmAclObj.getAccessorName(i);
      int permitType = dmAclObj.getAccessorPermitType(i);
      String principalName = principals.getPrincipalName(accessorName);
      if (principalName == null) {
        continue;
      }
      if (permitType == IDfPermitType.ACCESS_RESTRICTION) {
        if (dmAclObj.getAccessorPermit(i) <= IDfACL.DF_PERMIT_READ) {
          denies.add(principals.getPrincipal(accessorName, principalName,
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
            permits.add(principals.getPrincipal(accessorName, principalName,
                dmAclObj.isGroup(i)));
          }
        }
      }
    }

    return new Acl.Builder().setPermits(permits).setDenies(denies)
        .setEverythingCaseSensitive();
  }
}
