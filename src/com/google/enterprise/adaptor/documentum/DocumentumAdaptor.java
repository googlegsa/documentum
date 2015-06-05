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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Joiner;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.enterprise.adaptor.AbstractAdaptor;
import com.google.enterprise.adaptor.Acl;
import com.google.enterprise.adaptor.AdaptorContext;
import com.google.enterprise.adaptor.Config;
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.DocIdEncoder;
import com.google.enterprise.adaptor.DocIdPusher;
import com.google.enterprise.adaptor.DocIdPusher.Record;
import com.google.enterprise.adaptor.GroupPrincipal;
import com.google.enterprise.adaptor.IOHelper;
import com.google.enterprise.adaptor.InvalidConfigurationException;
import com.google.enterprise.adaptor.PollingIncrementalLister;
import com.google.enterprise.adaptor.Principal;
import com.google.enterprise.adaptor.Request;
import com.google.enterprise.adaptor.Response;

import com.documentum.com.DfClientX;
import com.documentum.com.IDfClientX;
import com.documentum.fc.client.IDfCollection;
import com.documentum.fc.client.IDfFolder;
import com.documentum.fc.client.IDfPersistentObject;
import com.documentum.fc.client.IDfQuery;
import com.documentum.fc.client.IDfSession;
import com.documentum.fc.client.IDfSessionManager;
import com.documentum.fc.client.IDfSysObject;
import com.documentum.fc.client.IDfType;
import com.documentum.fc.client.IDfVirtualDocument;
import com.documentum.fc.client.IDfVirtualDocumentNode;
import com.documentum.fc.common.DfException;
import com.documentum.fc.common.IDfAttr;
import com.documentum.fc.common.IDfId;
import com.documentum.fc.common.IDfLoginInfo;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.Charset;
import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/** Adaptor to feed Documentum repository content into a 
 *  Google Search Appliance.
 */
public class DocumentumAdaptor extends AbstractAdaptor implements
    PollingIncrementalLister {
  private static Logger logger =
      Logger.getLogger(DocumentumAdaptor.class.getName());

  /** Charset used in generated HTML responses. */
  private static final Charset CHARSET = Charset.forName("UTF-8");

  /** DQL Query to fetch all groups and their members. */
  private static final String ALL_GROUPS_QUERY = 
      "SELECT r_object_id, group_name, groups_names, users_names FROM dm_group";

  /** DQL Query to fetch only the local groups and their members. */
  private static final String LOCAL_GROUPS_QUERY = ALL_GROUPS_QUERY
      + " WHERE group_source IS NULL OR group_source <> 'LDAP'";

  /** DQL Query to fetch all users for dm_world magic group. */
  // TODO(bmj): Filter out disabled users (and do so in getPrincipal, too),
  // with user_state = 0 "indicating a user who can log in".
  private static final String ALL_USERS_QUERY = "SELECT user_name FROM dm_user"
      + " WHERE r_is_group IS NULL OR r_is_group = FALSE";

  private static final SimpleDateFormat dateFormat =
      new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

  // Initial checkpoints will have timestamps 24 hours in the past,
  // because Documentum timestamps are local server time.
  private static final String YESTERDAY = dateFormat.format(
      new Date(System.currentTimeMillis() - (24 * 60 * 60 * 1000L)));

  private final IDfClientX dmClientX;
  private List<String> startPaths;
  private CopyOnWriteArrayList<String> validatedStartPaths =
      new CopyOnWriteArrayList<String>();

  // The object attributes that should not be supplied as metadata.
  private Set<String> excludedAttributes;

  private DocIdEncoder docIdEncoder;
  private Config config;
  private IDfSessionManager dmSessionManager;
  private String docbase;
  private String globalNamespace;
  private String localNamespace;
  private String windowsDomain;
  private boolean pushLocalGroupsOnly;

  private Checkpoint modifiedAclsCheckpoint = new Checkpoint();
  private Checkpoint modifiedDocumentsCheckpoint = new Checkpoint();
  private Checkpoint modifiedGroupsCheckpoint = new Checkpoint();

  public static void main(String[] args) {
    AbstractAdaptor.main(new DocumentumAdaptor(), args);
  }

  /**
   * Remembers last objectId and its modification date for incremental updates.
   */
  static class Checkpoint {
    private final String lastModified;
    private final String objectId;

    public Checkpoint() {
      this(YESTERDAY, "0");
    }

    public Checkpoint(String lastModified, String objectId) {
      this.lastModified = lastModified;
      this.objectId = objectId;
    }

    public String getLastModified() {
      return lastModified;
    }

    public String getObjectId() {
      return objectId;
    }

    @Override
    public boolean equals(Object other) {
      // Simplified equals implementation good enough for the tests.
      if (other instanceof Checkpoint) {
        return toString().equals(((Checkpoint) other).toString());
      } else {
        return false;
      }
    }

    @Override
    public int hashCode() {
      return toString().hashCode();
    }

    @Override
    public String toString() {
      return "{" + lastModified + ", " + objectId + "}";
    }
  }

  // Returns a DocId of a path with optional name to append.
  @VisibleForTesting
  static DocId docIdFromPath(String path, String name) {
    if (Strings.isNullOrEmpty(name)) {
      return docIdFromPath(path);
    } else {
      return docIdFromPath(path + "/" + name);
    }
  }
  
  // Strip leading and trailing slashes so our DocIds show up
  // as children of the baseDocUrl.
  @VisibleForTesting
  static DocId docIdFromPath(String path) {
    return new DocId(path.substring(path.startsWith("/") ? 1 : 0,
        path.endsWith("/") ? path.length() - 1 : path.length()));
  }

  // Restore the leading slash, so we have a valid Documentum path.
  private static String docIdToPath(DocId docId) {
    return "/" + docId.getUniqueId();
  }

  private static String normalizePath(String path) {
    return docIdToPath(docIdFromPath(path));
  }

  public DocumentumAdaptor() {
    this(new DfClientX());
  }

  @VisibleForTesting
  DocumentumAdaptor(IDfClientX dmClientX) {
    this.dmClientX = dmClientX;
  }

  @Override
  public void initConfig(Config config) {
    config.addKey("documentum.username", null);
    config.addKey("documentum.password", null);
    config.addKey("documentum.docbaseName", null);
    config.addKey("documentum.src", null);
    config.addKey("documentum.separatorRegex", ",");
    config.addKey("adaptor.namespace", Principal.DEFAULT_NAMESPACE);
    config.addKey("documentum.windowsDomain", "");
    config.addKey("documentum.pushLocalGroupsOnly", "false");
    config.addKey("documentum.excludedAttributes", "a_application_type, "
        + "a_archive, a_category, a_compound_architecture, a_controlling_app, "
        + "a_effective_date, a_effective_flag, a_effective_label, "
        + "a_expiration_date, a_extended_properties, a_full_text, a_is_hidden, "
        + "a_is_signed, a_is_template, a_last_review_date, a_link_resolved, "
        + "a_publish_formats, a_retention_date, a_special_app, a_status, "
        + "a_storage_type, acl_domain, acl_name, group_name, group_permit, "
        + "i_ancestor_id, i_antecedent_id, i_branch_cnt, i_cabinet_id, "
        + "i_chronicle_id, i_contents_id, i_direct_dsc, i_folder_id, "
        + "i_has_folder, i_is_deleted, i_is_reference, i_is_replica, "
        + "i_latest_flag, i_partition, i_reference_cnt, i_retain_until, "
        + "i_retainer_id, i_vstamp, language_code, log_entry, owner_permit, "
        + "r_access_date, r_alias_set_id, r_aspect_name, r_assembled_from_id, "
        + "r_component_label, r_composite_id, r_composite_label, "
        + "r_current_state, r_folder_path, r_frozen_flag, r_frzn_assembly_cnt, "
        + "r_full_content_size, r_has_events, r_has_frzn_assembly, "
        + "r_immutable_flag, r_is_public, r_is_virtual_doc, r_link_cnt, "
        + "r_link_high_cnt, r_lock_date, r_lock_machine, r_lock_owner, "
        + "r_modifier, r_order_no, r_page_cnt, r_policy_id, r_resume_state, "
        + "r_version_label, resolution_label, world_permit");
  }

  @Override
  public void init(AdaptorContext context) throws DfException {
    docIdEncoder = context.getDocIdEncoder();
    config = context.getConfig();
    validateConfig(config);
    docbase = config.getValue("documentum.docbaseName").trim();
    globalNamespace = config.getValue("adaptor.namespace").trim();
    logger.log(Level.CONFIG, "adaptor.namespace: {0}", globalNamespace);
    localNamespace = globalNamespace + "_" + docbase;
    logger.log(Level.CONFIG, "local namespace: {0}", localNamespace);
    windowsDomain = config.getValue("documentum.windowsDomain").trim();
    logger.log(Level.CONFIG, "documentum.windowsDomain: {0}", windowsDomain);
    pushLocalGroupsOnly = Boolean.parseBoolean(
        config.getValue("documentum.pushLocalGroupsOnly"));
    logger.log(Level.CONFIG, "documentum.pushLocalGroupsOnly: {0}", 
        pushLocalGroupsOnly);
    String src = config.getValue("documentum.src");
    logger.log(Level.CONFIG, "documentum.src: {0}", src);
    String separatorRegex = config.getValue("documentum.separatorRegex");
    logger.log(Level.CONFIG, "documentum.separatorRegex: {0}", separatorRegex);
    startPaths = parseStartPaths(src, separatorRegex);
    logger.log(Level.CONFIG, "start paths: {0}", startPaths);
    String excludedAttrs = config.getValue("documentum.excludedAttributes");
    excludedAttributes = ImmutableSet.copyOf(Splitter.on(",")
        .trimResults().omitEmptyStrings().split(excludedAttrs));
    logger.log(Level.CONFIG, "documentum.excludedAttributes: {0}",
        excludedAttrs);

    initDfc(config);
    dmSessionManager = getDfcSessionManager(config);
    IDfSession dmSession = dmSessionManager.getSession(docbase);
    try {
      validateStartPaths(dmSession);
    } finally {
      dmSessionManager.release(dmSession);
    }
    if (validatedStartPaths.isEmpty()) {
      throw new IllegalStateException(
         "Failed to validate documentum.src paths.");
    }
  }

  private static void validateConfig(Config config) {
    if (Strings.isNullOrEmpty(config.getValue("documentum.username"))) {
      throw new InvalidConfigurationException(
          "documentum.username is required");
    }
    if (Strings.isNullOrEmpty(config.getValue("documentum.password"))) {
      throw new InvalidConfigurationException(
          "documentum.password is required");
    }
    if (Strings.isNullOrEmpty(config.getValue("documentum.docbaseName"))) {
      throw new InvalidConfigurationException(
          "documentum.docbaseName is required");
    }
    if (Strings.isNullOrEmpty(config.getValue("documentum.src"))) {
      throw new InvalidConfigurationException(
          "documentum.src is required");
    }
  }

  @VisibleForTesting
  static List<String> parseStartPaths(String paths, String separatorRegex) {
    if (separatorRegex.isEmpty()) {
      return ImmutableList.of(paths);
    } else {
      return ImmutableList.copyOf(Splitter.on(Pattern.compile(separatorRegex))
          .trimResults().omitEmptyStrings().split(paths));
    }
  }

  /**
   * Validate start paths and add the valid ones to validatedStartPaths list.
   */
  private void validateStartPaths(IDfSession dmSession) {
    List<String> validStartPaths = new ArrayList<String>(startPaths.size());
    for (String startPath : startPaths) {
      String documentumFolderPath = normalizePath(startPath);
      logger.log(Level.INFO, "Validating path {0}", documentumFolderPath);
      try {
        IDfSysObject obj =
            (IDfSysObject) dmSession.getObjectByPath(documentumFolderPath);
        if (obj == null) {
          logger.log(Level.WARNING, "Invalid start path {0}",
              documentumFolderPath);
        } else {
          logger.log(Level.CONFIG, "Valid start path {0} id:{1}", new Object[] {
              documentumFolderPath, obj.getObjectId().toString()});
          validStartPaths.add(documentumFolderPath);
        }
      } catch (DfException e) {
        logger.log(Level.WARNING, "Error validating start path {0}: {1}",
            new Object[] { documentumFolderPath, e.getMessage() });
      }
    }
    validatedStartPaths.addAllAbsent(validStartPaths);
  }

  @VisibleForTesting
  List<String> getStartPaths() {
    return Collections.unmodifiableList(startPaths);
  }

  @VisibleForTesting
  List<String> getValidatedStartPaths() {
    return Collections.unmodifiableList(validatedStartPaths);
  }

  /** Get all doc ids from Documentum repository. 
   * @throws InterruptedException if pusher is interrupted in sending Doc Ids.
   * @throws IOException if error in getting Acl information.
   */
  @Override
  public void getDocIds(DocIdPusher pusher) throws InterruptedException,
      IOException {
    logger.entering("DocumentumAdaptor", "getDocIds");
    IDfSession dmSession;
    try {
      dmSession = dmSessionManager.getSession(docbase);
    } catch (DfException e) {
      throw new IOException("Failed to get Documentum Session", e);
    }
    try {
      // Push the start paths to initiate crawl.
      validateStartPaths(dmSession);
      ArrayList<DocId> docIds = new ArrayList<DocId>();
      for (String startPath : validatedStartPaths) {
        docIds.add(docIdFromPath(startPath));
      }
      logger.log(Level.FINER, "DocumentumAdaptor DocIds: {0}", docIds);
      pusher.pushDocIds(docIds);

      // Push the ACLs and Groups.
      DfException savedException = null;
      Principals principals = new Principals(dmSession, localNamespace,
          globalNamespace, windowsDomain);
      try {
        pusher.pushNamedResources(
            new DocumentumAcls(dmClientX, dmSession, principals).getAcls());
      } catch (DfException e) {
        savedException = e;
      }
      try {
        pusher.pushGroupDefinitions(
            getGroups(dmClientX, dmSession, principals, pushLocalGroupsOnly),
            /* case sensitive */ true);
      } catch (DfException e) {
        if (savedException == null) {
          savedException = e;
        } else {
          savedException.addSuppressed(e);
        }
      }
      if (savedException != null) {
        throw new IOException(savedException);
      }
    } finally {
      dmSessionManager.release(dmSession);
    }
    logger.exiting("DocumentumAdaptor", "getDocIds");
  }

  /** Returns a map of groups and their members. */
  @VisibleForTesting
  Map<GroupPrincipal, Collection<Principal>> getGroups(IDfClientX dmClientX,
      IDfSession session, Principals principals, boolean localGroupsOnly)
      throws DfException {
    IDfQuery query = dmClientX.getQuery();
    query.setDQL(localGroupsOnly ? LOCAL_GROUPS_QUERY : ALL_GROUPS_QUERY);
    IDfCollection result = query.execute(session, IDfQuery.DF_EXECREAD_QUERY);
    try {
      ImmutableMap.Builder<GroupPrincipal, Collection<Principal>> groups =
          ImmutableMap.builder();
      while (result.next()) {
        addGroup(groups, principals, result);
      }
      // Add special dm_world group, which is all users.
      GroupPrincipal groupPrincipal = (GroupPrincipal)
          principals.getPrincipal("dm_world", "dm_world", true);
      groups.put(groupPrincipal, getDmWorldPrincipals(session, principals));
      return groups.build();
    } finally {
      result.close();
    }
  }

  /** Adds a group and its members to the collection of groups. */
  private void addGroup(
      ImmutableMap.Builder<GroupPrincipal, Collection<Principal>> groups,
      Principals principals, IDfCollection result) throws DfException {
    String groupName = result.getString("group_name");
    logger.log(Level.FINE, "Found Group: {0}", groupName);
    String principalName = principals.getPrincipalName(groupName);
    if (principalName != null) {
      GroupPrincipal groupPrincipal = (GroupPrincipal)
          principals.getPrincipal(groupName, principalName, true);
      ImmutableSet.Builder<Principal> builder = ImmutableSet.builder();
      // All the member users are in one repeating value, all the member
      // groups are in another repeating value.
      addMemberPrincipals(builder, principals, result, "users_names", false);
      addMemberPrincipals(builder, principals, result, "groups_names", true);
      ImmutableSet<Principal> members = builder.build();
      logger.log(Level.FINEST, "Pushing Group {0}: {1}",
           new Object[] { principalName, members });
      groups.put(groupPrincipal, members);
    }
  }

  /** Adds Principals for all the users or groups to the set of members. */
  // TODO(bmj): Apparently repeating values on DB2 backends may not work here.
  private void addMemberPrincipals(ImmutableSet.Builder<Principal> members,
      Principals principals, IDfCollection result, String attributeName,
      boolean isGroup) throws DfException {
    int numMembers = result.getValueCount(attributeName);
    for (int i = 0; i < numMembers; i++) {
      String member = result.getRepeatingString(attributeName, i);
      String principalName = principals.getPrincipalName(member);
      if (principalName != null) {
        members.add(principals.getPrincipal(member, principalName, isGroup));
      }
    }
  }

  /** Adds Principals for all users in special dm_world group to members. */
  private Collection<Principal> getDmWorldPrincipals(IDfSession session,
      Principals principals) throws DfException {
    IDfQuery query = dmClientX.getQuery();
    query.setDQL(ALL_USERS_QUERY);
    IDfCollection result = query.execute(session, IDfQuery.DF_EXECREAD_QUERY);
    try {
      ImmutableSet.Builder<Principal> members = ImmutableSet.builder();
      while (result.next()) {
        String member = result.getString("user_name");
        String principalName = principals.getPrincipalName(member);
        if (principalName != null) {
          members.add(principals.getPrincipal(member, principalName, false));
        }
      }      
      return members.build();
    } finally {
      result.close();
    }
  }

  @Override
  public void getModifiedDocIds(DocIdPusher pusher) throws IOException,
      InterruptedException {
    logger.entering("DocumentumAdaptor", "getModifiedDocIds");
    IDfSession dmSession;
    try {
      dmSession = dmSessionManager.getSession(docbase);
    } catch (DfException e) {
      throw new IOException("Failed to get Documentum Session", e);
    }
    try {
      DfException savedException = null;

      // Push modified documents.
      try {
        validateStartPaths(dmSession);
        modifiedDocumentsCheckpoint = pushDocumentUpdates(pusher, dmClientX, 
            dmSession, validatedStartPaths, modifiedDocumentsCheckpoint);
      } catch (DfException e) {
        savedException = e;
      }
      
      Principals principals = new Principals(dmSession, localNamespace,
          globalNamespace, windowsDomain);
      try {
        modifiedAclsCheckpoint = pushAclUpdates(pusher, dmClientX, dmSession,
          principals, modifiedAclsCheckpoint);
      } catch (DfException e) {
        savedException = e;
      }

      try {
        modifiedGroupsCheckpoint = pushGroupUpdates(pusher, dmClientX,
            dmSession, principals, pushLocalGroupsOnly, 
            modifiedGroupsCheckpoint);
      } catch (DfException e) {
        savedException = e;
      }

      if (savedException != null) {
        throw new IOException(savedException);
      }
    } finally {
      dmSessionManager.release(dmSession);
    }
    logger.exiting("DocumentumAdaptor", "getModifiedDocIds");
  }

  /**
   * Push ACL updates to GSA.
   */
  private Checkpoint pushAclUpdates(DocIdPusher pusher, IDfClientX dmClientX,
      IDfSession session, Principals principals, Checkpoint checkpoint)
      throws DfException, IOException, InterruptedException {
    DocumentumAcls dctmAcls =
        new DocumentumAcls(dmClientX, session, principals);
    Map<DocId, Acl> aclMap = dctmAcls.getUpdateAcls(checkpoint);
    pusher.pushNamedResources(aclMap);
    return dctmAcls.getUpdateAclsCheckpoint();
  }

  /**
   * Push Document updates to GSA.
   */
  @VisibleForTesting
  Checkpoint pushDocumentUpdates(DocIdPusher pusher, IDfClientX dmClientX,
      IDfSession session, List<String> startPaths, Checkpoint checkpoint)
      throws DfException, IOException, InterruptedException {
    String queryStr = makeUpdatedDocsQuery(startPaths, checkpoint);
    logger.log(Level.FINER, "Modified DocIds Query: {0}", queryStr);
    IDfQuery query = dmClientX.getQuery();
    query.setDQL(queryStr);
    IDfCollection result = query.execute(session, IDfQuery.DF_EXECREAD_QUERY);
    try {
      String lastModified = checkpoint.getLastModified();
      String objectId = checkpoint.getObjectId();
      ImmutableList.Builder<Record> builder = ImmutableList.builder();
      while (result.next()) {
        lastModified = result.getString("r_modify_date_str");
        objectId = result.getString("r_object_id");
        IDfType type = session.getType(result.getString("r_object_type"));
        if (type.isTypeOf("dm_folder")) {
          addUpdatedDocIds(builder, session, startPaths, objectId, null);
        } else if (type.isTypeOf("dm_document")) {
          String name = result.getString("object_name");
          int numFolders = result.getValueCount("i_folder_id");
          for (int i = 0; i < numFolders; i++) {
            String folderId = result.getRepeatingString("i_folder_id", i);
            addUpdatedDocIds(builder, session, startPaths, folderId, name);
          }
        }
      }
      List<Record> records = builder.build();
      logger.log(Level.FINER, "DocumentumAdaptor Modified DocIds: {0}",
          records);
      pusher.pushRecords(records);
      return new Checkpoint(lastModified, objectId);
    } finally {
      result.close();
    }
  }

  /**
   * A document can reside under multiple folder paths.
   * Only push those paths that are under our start paths.
   *
   * @param builder builder for list of DocIds
   * @param folderId the ID of a Documentum folder
   * @param name the document name to append to the folder
   *    paths for a document, or null for a folder
   */
  private void addUpdatedDocIds(ImmutableList.Builder<Record> builder,
      IDfSession session, List<String> startPaths, String folderId, String name)
      throws DfException {
    IDfFolder folder = session.getFolderBySpecification(folderId);
    if (folder != null) {
      for (int i = 0; i < folder.getFolderPathCount(); i++) {
        String path = folder.getFolderPath(i);
        if (isUnderStartPath(path, startPaths)) {
          builder.add(new Record.Builder(docIdFromPath(path, name))
              .setCrawlImmediately(true).build());
        }
      }
    }
  }

  private String makeUpdatedDocsQuery(List<String> startPaths,
      Checkpoint checkpoint) {
    StringBuilder query = new StringBuilder();
    query.append("SELECT object_name, r_object_id, r_object_type, ")
        .append("i_folder_id, r_modify_date, ")
        .append("DATETOSTRING(r_modify_date, 'yyyy-mm-dd hh:mi:ss') ")
        .append("AS r_modify_date_str FROM dm_sysobject ")
        // Limit the returned object types to dm_document, dm_folder,
        // or any type that is a subtype of dm_document or dm_folder.
       .append("WHERE (TYPE(dm_document) OR TYPE(dm_folder)) AND ")
       .append(MessageFormat.format(
            "((r_modify_date = DATE(''{0}'',''yyyy-mm-dd hh:mi:ss'') AND "
            + "r_object_id > ''{1}'') OR (r_modify_date > DATE(''{0}'',"
            + "''yyyy-mm-dd hh:mi:ss'')))",
            checkpoint.getLastModified(), checkpoint.getObjectId()));

    // Limit our search to modified docs under a start path.
    query.append(" AND (FOLDER('");
    Joiner.on("',descend) OR FOLDER('").appendTo(query, startPaths);
    query.append("',descend)) ORDER BY r_modify_date, r_object_id");
    return query.toString();
  }

  /**
   * Push Group updates to GSA.
   */
  @VisibleForTesting
  Checkpoint pushGroupUpdates(DocIdPusher pusher, IDfClientX dmClientX,
      IDfSession session, Principals principals, boolean localGroupsOnly,
      Checkpoint checkpoint)
      throws DfException, IOException, InterruptedException {
    String queryStr = makeUpdatedGroupsQuery(localGroupsOnly, checkpoint);
    logger.log(Level.FINER, "Modified Groups Query: {0}", queryStr);
    IDfQuery query = dmClientX.getQuery();
    query.setDQL(queryStr);
    IDfCollection result = query.execute(session, IDfQuery.DF_EXECREAD_QUERY);
    try {
      String lastModified = checkpoint.getLastModified();
      String objectId = checkpoint.getObjectId();
      ImmutableMap.Builder<GroupPrincipal, Collection<Principal>> groups =
          ImmutableMap.builder();
      while (result.next()) {
        lastModified = result.getString("r_modify_date_str");
        objectId = result.getString("r_object_id");
        addGroup(groups, principals, result);
      }
      pusher.pushGroupDefinitions(groups.build(), /* case sensitive */ true);
      return new Checkpoint(lastModified, objectId);
    } finally {
      result.close();
    }
  }

  private String makeUpdatedGroupsQuery(boolean localGroupsOnly,
      Checkpoint checkpoint) {
    StringBuilder query = new StringBuilder();
    query.append("SELECT r_object_id, group_name, groups_names, users_names, ")
        .append("r_modify_date, ")
        .append("DATETOSTRING(r_modify_date, 'yyyy-mm-dd hh:mi:ss') ")
        .append("AS r_modify_date_str FROM dm_group WHERE ")
        .append(MessageFormat.format(
            "((r_modify_date = DATE(''{0}'',''yyyy-mm-dd hh:mi:ss'') AND "
            + "r_object_id > ''{1}'') OR (r_modify_date > DATE(''{0}'',"
            + "''yyyy-mm-dd hh:mi:ss'')))",
            checkpoint.getLastModified(), checkpoint.getObjectId()));
    if (localGroupsOnly) {
      query.append(" AND (group_source IS NULL OR group_source <> 'LDAP')");
    }
    return query.toString();
  }

  /** Gives the bytes of a document referenced with id. 
   *
   * @throws IOException if a Documentum error occurs
   */
  @Override
  public void getDocContent(Request req, Response resp) throws IOException {
    // TODO: (sveldurthi) support "/" as start path, to process all cabinets.
    // TODO: (sveldurthi) validate the requested doc id is in start paths,
    //       if not send a 404.
    getDocContentHelper(req, resp, dmSessionManager, docIdEncoder,
        validatedStartPaths, excludedAttributes);
  }

  @VisibleForTesting
  void getDocContentHelper(Request req, Response resp,
      IDfSessionManager dmSessionManager, DocIdEncoder docIdEncoder,
      List<String> validatedStartPaths, Set<String> excludedAttributes)
      throws IOException {
    DocId id = req.getDocId();
    logger.log(Level.FINER, "Get content for id: {0}", id);

    String path = docIdToPath(id);
    if (!isUnderStartPath(path, validatedStartPaths)) {
      resp.respondNotFound();
      return;
    }

    IDfSession dmSession;
    try {
      dmSession = dmSessionManager.getSession(docbase);

      IDfPersistentObject dmPersObj = dmSession.getObjectByPath(path);
      if (dmPersObj == null) {
        logger.log(Level.FINER, "Not found: {0}", id);
        resp.respondNotFound();
        return;
      }

      IDfId dmObjId = dmPersObj.getObjectId();
      IDfType type = dmPersObj.getType();
      logger.log(Level.FINER, "Object Id: {0}; Type: {1}",
          new Object[] {dmObjId, type.getName()});

      if (type.isTypeOf("dm_document")) {
        getDocumentContent(resp, (IDfSysObject) dmPersObj, id, docIdEncoder,
            excludedAttributes);
      } else if (type.isTypeOf("dm_folder")) {
        getFolderContent(resp, (IDfFolder) dmPersObj, id, docIdEncoder,
            excludedAttributes);
      } else {
        logger.log(Level.WARNING, "Unsupported type: {0}", type);
        resp.respondNotFound();
      }
    } catch (DfException e) {
      throw new IOException("Error getting content:", e);
    }
  }

  /**
   * Returns {@code true} if the supplied {@code path} is under one of the
   * validated {@code startPaths}, {@code false} otherwise.
   *
   * @param path a String representing a possible path to a document
   */
  private boolean isUnderStartPath(String path, List<String> startPaths) {
    for (String startPath : startPaths) {
      if (startPath.equals(path) || path.startsWith(startPath + "/")) {
        return true;
      }
    }
    return false;
  }

  /** Copies the Documentum document content into the response. */
  private void getDocumentContent(Response resp, IDfSysObject dmSysbObj,
      DocId id, DocIdEncoder docIdEncoder, Set<String> excludedAttributes)
      throws DfException, IOException {
    // Include document attributes as metadata.
    getMetadata(resp, dmSysbObj, id, excludedAttributes);

    // If it is a virtual document, include links to the child documents.
    if (dmSysbObj.isVirtualDocument()) {
      getVdocChildLinks(resp, dmSysbObj, id, docIdEncoder);
    }

    // Return the content.
    String contentType = dmSysbObj.getContentType();
    logger.log(Level.FINER, "Content Type: {0}", contentType);
    resp.setContentType(contentType);
    try (InputStream inStream = dmSysbObj.getContent()) {
      IOHelper.copyStream(inStream, resp.getOutputStream());
    }
  }

  /** Supplies the document attributes as metadata in the response. */
  private void getMetadata(Response resp, IDfSysObject dmSysbObj, DocId id,
      Set<String> excludedAttributes) throws DfException, IOException {
    Set<String> attributeNames = getAttributeNames(dmSysbObj);
    for (String name : attributeNames) {
      if (!excludedAttributes.contains(name)) {
        int count = dmSysbObj.getValueCount(name);
        for (int i = 0; i < count; i++) {
          String value = dmSysbObj.getRepeatingString(name, i);
          if (value != null) {
            logger.log(Level.FINEST, "Attribute: {0} = {1}",
                new Object[] { name, value });
            resp.addMetadata(name, value);
          }
        }
      }
    }
  }

  /** Returns the names of all the attributes on this object. */
  // TODO(bmj): Cache this set, keyed of the objectType, filtered of
  // excluded attrs. The set of metadata is the same for all items
  // of a specific type.
  private Set<String> getAttributeNames(IDfSysObject sysObject)
      throws DfException {
    @SuppressWarnings("unchecked")
    Enumeration<IDfAttr> e = sysObject.enumAttrs();
    ImmutableSet.Builder<String> builder = ImmutableSet.builder();
    while (e.hasMoreElements()) {
      builder.add(e.nextElement().getName());
    }
    return builder.build();
  }

  /** Supplies VDoc children as external link metadata in the response. */
  private void getVdocChildLinks(Response resp, IDfSysObject dmSysbObj,
      DocId id, DocIdEncoder docIdEncoder) throws DfException, IOException {
    IDfVirtualDocument vDoc = dmSysbObj.asVirtualDocument("CURRENT", false);
    IDfVirtualDocumentNode root = vDoc.getRootNode();
    int count = root.getChildCount();
    for (int i = 0; i < count; i++) {
      IDfSysObject child = root.getChild(i).getSelectedObject();
      String objId = child.getString("r_object_id");
      String objName = child.getString("object_name");
      logger.log(Level.FINER, "VDoc Child Object Id: {0}; Name: {1}",
          new Object[] {objId, objName});
      DocId childDocId = docIdFromPath(docIdToPath(id), objName);
      resp.addAnchor(docIdEncoder.encodeDocId(childDocId), objName);
    }
  }

  /** Returns the Folder's contents as links in a generated HTML document. */
  private void getFolderContent(Response resp, IDfFolder dmFolder, DocId id,
      DocIdEncoder docIdEncoder, Set<String> excludedAttributes) 
      throws DfException, IOException {
    // Include folder attributes as metadata.
    getMetadata(resp, dmFolder, id, excludedAttributes);

    logger.log(Level.FINER, "Listing contents of folder: {0} ",
        dmFolder.getObjectName());
    IDfCollection dmCollection =
        dmFolder.getContents("r_object_id, object_name");

    try (HtmlResponseWriter htmlWriter =
         createHtmlResponseWriter(resp, docIdEncoder)) {
      htmlWriter.start(id, dmFolder.getObjectName());
      while (dmCollection.next()) {
        String objId = dmCollection.getString("r_object_id");
        String objName = dmCollection.getString("object_name");
        logger.log(Level.FINER, "Object Id: {0}; Name: {1}",
            new Object[] {objId, objName});
        DocId childDocId = docIdFromPath(docIdToPath(id), objName);
        htmlWriter.addLink(childDocId, objName);
      }
      htmlWriter.finish();
    } finally {
      try {
        dmCollection.close();
      } catch (DfException e) {
        logger.log(Level.WARNING, "Error closing collection", e);
      }
    }
  }

  private HtmlResponseWriter createHtmlResponseWriter(Response response,
      DocIdEncoder docIdEncoder) throws IOException {
    response.setContentType("text/html; charset=" + CHARSET.name());
    Writer writer = new OutputStreamWriter(response.getOutputStream(), CHARSET);
    // TODO(ejona): Get locale from request.
    return new HtmlResponseWriter(writer, docIdEncoder, Locale.ENGLISH);
  }

  /**
   * Establishes connection DFC.
   * 
   * @param config Adaptor config object
   * @throws DfException if error in getting local client or error in setting 
   *         repository identity, or error in getting session, or error in 
   *         getting server version.
   */
  private void initDfc(Config config) throws DfException {
    IDfSessionManager dmSessionManager = getDfcSessionManager(config);

    String username = config.getValue("documentum.username");
    String docbaseName = config.getValue("documentum.docbaseName");
    logger.log(Level.CONFIG, "documentum.username: {0}", username);
    logger.log(Level.CONFIG, "documentum.docbaseName: {0}", docbaseName);

    IDfSession dmSession = dmSessionManager.getSession(docbaseName);
    logger.log(Level.FINE, "Session Manager set the identity for {0}",
        username);
    logger.log(Level.INFO, "DFC {0} connected to Content Server {1}",
        new Object[] {dmClientX.getDFCVersion(), dmSession.getServerVersion()});
    logger.log(Level.INFO, "Created a new session for the docbase {0}",
        docbaseName);

    logger.log(Level.INFO, "Releasing dfc session for {0}", docbaseName);
    dmSessionManager.release(dmSession);
  }

  /**
   * Gets DFC Session manager.
   * 
   * @param config Adaptor config object
   * @return IDfSessionManager returns a new session manager for the configured 
   *         username and docbaseName
   * @throws DfException if error in getting local client or error in setting 
   *         repository identity.
   */
  private IDfSessionManager getDfcSessionManager(Config config)
      throws DfException {
    IDfSessionManager dmSessionManager =
        dmClientX.getLocalClient().newSessionManager();
    IDfLoginInfo dmLoginInfo = dmClientX.getLoginInfo();

    String username = config.getValue("documentum.username");
    String password = config.getValue("documentum.password");
    String docbaseName = config.getValue("documentum.docbaseName");

    dmLoginInfo.setUser(username);
    dmLoginInfo.setPassword(password);
    dmSessionManager.setIdentity(docbaseName, dmLoginInfo);

    return dmSessionManager;
  }
}
