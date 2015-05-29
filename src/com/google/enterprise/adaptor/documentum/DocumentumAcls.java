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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
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

import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
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

  @VisibleForTesting
  static final String DATE_FORMAT = "yyyy-MM-dd HH:mm:ss";

  private static String aclModifiedDate;
  private static String aclModifyId;

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
    // TODO(jlacey): We don't need the ORDER BY clause.
    IDfQuery query = dmClientX.getQuery();
    query.setDQL("select r_object_id from dm_acl order by r_object_id");
    return query;
  }

  private IDfQuery makeUpdateAclQuery() {
    StringBuilder queryStr = new StringBuilder(
        "select r_object_id, chronicle_id, audited_obj_id, event_name, "
        + "time_stamp_utc, "
        + "DATETOSTRING(time_stamp_utc, 'yyyy-mm-dd hh:mi:ss') "
        + "as time_stamp_utc_str "
        + "from dm_audittrail_acl "
        + "where (event_name='dm_save' or event_name='dm_saveasnew' "
        + "or event_name='dm_destroy')");

    String whereBoundedClause = " and ((time_stamp_utc = "
        + "date(''{0}'',''yyyy-mm-dd hh:mi:ss'') and (r_object_id > ''{1}'')) "
        + "OR (time_stamp_utc > date(''{0}'',''yyyy-mm-dd hh:mi:ss'')))";

    if (Strings.isNullOrEmpty(aclModifiedDate)) {
      aclModifiedDate = new SimpleDateFormat(DATE_FORMAT).format(new Date());
      logger.log(Level.FINE, "Setting ModifiedDate to now: {0}",
          aclModifiedDate);
      aclModifyId = "0";
    }

    // TODO (Srinivas): Adjust modified date to server TZ offset
    Object[] arguments = {aclModifiedDate, aclModifyId};
    queryStr.append(MessageFormat.format(whereBoundedClause, arguments));
    queryStr.append(" order by time_stamp_utc, r_object_id, event_name");
    logger.log(Level.FINE, "Modify date: {0} ; Modify ID: {1}", arguments);
    logger.log(Level.FINER, "Update ACL query: {0}", queryStr);

    IDfQuery query = dmClientX.getQuery();
    query.setDQL(queryStr.toString());
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
        addAclChainToMap(dmAcl, objectId, aclMap);
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
   * Returns all updated Documentum ACLs in map with doc id and Acl.
   *
   * In Documentum, ACLs are high level objects separate from content objects.
   * An ACL can be applied to one or many content objects. Or, each object
   * can have it's own individual ACL applied to it. So this method needs to
   * send all the ACLs in Documentum to GSA.
   *
   * @return Documentum ACLs in map
   * @throws DfException if error in getting ACL information.
   */
  public Map<DocId, Acl> getUpdateAcls() throws DfException {
    HashSet<String> aclModifiedIds = new HashSet<String>();
    IDfQuery query = makeUpdateAclQuery();
    IDfCollection dmAclCollection =
        query.execute(dmSession, IDfQuery.DF_EXECREAD_QUERY);
    try {
      Map<DocId, Acl> aclMap = new HashMap<DocId, Acl>();
      while (dmAclCollection.next()) {
        aclModifiedDate = dmAclCollection.getString("time_stamp_utc_str");
        aclModifyId = dmAclCollection.getString("r_object_id");
        String chronicleId = dmAclCollection.getString("chronicle_id");
        String modifyObjectId = dmAclCollection.getString("audited_obj_id");

        if (aclModifiedIds.contains(chronicleId)) {
          logger.log(Level.FINE,
              "Skipping redundant modify of: {0}", chronicleId);
          continue;
        }
        IDfACL dmAcl = (IDfACL) dmSession.getObject(new DfId(modifyObjectId));
        addAclChainToMap(dmAcl, modifyObjectId, aclMap);
        aclModifiedIds.add(chronicleId);
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
   * Adds all of the Adaptor Acls for the Documentum ACL to the map.
   *
   * @param dmAcl Documentum ACL object.
   * @param objectId Documentum ACL object id.
   * @param aclMap Map with doc id and acl.
   * @throws DfException if error in getting acl info.
   */
  private void addAclChainToMap(IDfACL dmAcl, String objectId,
      Map<DocId, Acl> aclMap) throws DfException {
    List<String> requiredGroupSet = new ArrayList<String>();
    String parentAclId = null;
    Set<Principal> permits = new HashSet<Principal>();
    Set<Principal> denies = new HashSet<Principal>();

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
      } else {
        processBasicPermissions(accessorName, permitType,
            dmAcl.getAccessorPermit(i), dmAcl.isGroup(i), permits, denies);
      }
    }

    if (!requiredGroupSet.isEmpty()) {
      String aclId = objectId + "_reqGroupSet";
      Acl acl = getRequiredAcl(parentAclId, requiredGroupSet);
      aclMap.put(new DocId(aclId), acl);
      parentAclId = aclId;
    }

    Acl acl = getBasicAcl(objectId, parentAclId, permits, denies);
    aclMap.put(new DocId(objectId), acl);
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
   * Creates a principal for an ACL entry with basic permissions.
   * Populates permits set with users and groups with READ permission.
   * Populates denies set with users and groups with no READ
   * permission.
   *
   * @param accessorName the ACL entry accessor name
   * @param permitType the type of the ACL entry (required group,
   *     access permit, etc.)
   * @param accessorPermit the access permission of the ACL entry
   * @param isGroup {@code true} iff the accessor is a group
   * @param permits the set of permitted principals to populate
   * @param denies the set of denied principals to populate
   * @throws DfException if error in getting user or group information.
   */
  private void processBasicPermissions(String accessorName, int permitType,
      int accessorPermit, boolean isGroup, Set<Principal> permits,
      Set<Principal> denies) throws DfException {
    // TODO(jlacey): We need to call this for required groups, too.
    String principalName = principals.getPrincipalName(accessorName);
    if (principalName == null) {
      return;
    }
    if (permitType == IDfPermitType.ACCESS_RESTRICTION) {
      if (accessorPermit <= IDfACL.DF_PERMIT_READ) {
        denies.add(
            principals.getPrincipal(accessorName, principalName, isGroup));
      }
    } else if (permitType == IDfPermitType.ACCESS_PERMIT) {
      if (accessorPermit >= IDfACL.DF_PERMIT_READ) {
        if (accessorName.equalsIgnoreCase("dm_owner")
            || accessorName.equalsIgnoreCase("dm_group")) {
          // skip dm_owner and dm_group for now.
          // TODO (Srinivas): Need to resolve these acls for
          //      both allow and deny.
          return;
        } else {
          permits.add(
              principals.getPrincipal(accessorName, principalName, isGroup));
        }
      }
    }
  }

  /*
   * Creates an Adaptor Acl for the basic permissions in the ACL
   * object.
   *
   * @param objectId Documentum ACL object ID
   * @param parentAclId the doc ID of the parent ACL in the chain
   * @param permits the principals permitted access
   * @param denies the principals denied access
   * @return Adaptor Acl object
   * @throws DfException if error in getting user or group information.
   */
  private Acl getBasicAcl(String objectId, String parentAclId,
      Set<Principal> permits, Set<Principal> denies) throws DfException {
    Acl.Builder builder = new Acl.Builder()
        .setPermits(permits).setDenies(denies)
        .setEverythingCaseSensitive()
        .setInheritanceType(Acl.InheritanceType.PARENT_OVERRIDES);
    if (parentAclId != null) {
      logger.log(Level.FINE,
          "ACL {0} has required groups or required group set", objectId);
      builder.setInheritFrom(new DocId(parentAclId));
    }
    return builder.build();
  }
}
