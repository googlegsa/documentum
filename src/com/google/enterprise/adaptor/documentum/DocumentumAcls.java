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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Returns all Documentum ACLs in map with doc id as key and Acl as value.
 */
public class DocumentumAcls {
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
        .setInheritanceType(Acl.InheritanceType.PARENT_OVERRIDES)
        .setEverythingCaseSensitive().build();
  }
}
