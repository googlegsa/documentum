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
import com.documentum.fc.client.IDfEnumeration;
import com.documentum.fc.client.IDfFolder;
import com.documentum.fc.client.IDfObjectPath;
import com.documentum.fc.client.IDfPersistentObject;
import com.documentum.fc.client.IDfQuery;
import com.documentum.fc.client.IDfSession;
import com.documentum.fc.client.IDfSessionManager;
import com.documentum.fc.client.IDfSysObject;
import com.documentum.fc.client.IDfType;
import com.documentum.fc.client.IDfVirtualDocument;
import com.documentum.fc.client.IDfVirtualDocumentNode;
import com.documentum.fc.common.DfException;
import com.documentum.fc.common.DfId;
import com.documentum.fc.common.IDfAttr;
import com.documentum.fc.common.IDfId;
import com.documentum.fc.common.IDfLoginInfo;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

/** Adaptor to feed Documentum repository content into a 
 *  Google Search Appliance.
 */
public class DocumentumAdaptor extends AbstractAdaptor implements
    PollingIncrementalLister {
  private static Logger logger =
      Logger.getLogger(DocumentumAdaptor.class.getName());

  /** Charset used in generated HTML responses. */
  private static final Charset CHARSET = Charset.forName("UTF-8");

  /** DQL Query to fetch all users for dm_world magic group. */
  private static final String ALL_USERS_QUERY = "SELECT user_name FROM dm_user"
      + " WHERE user_state = 0 AND (r_is_group IS NULL OR r_is_group = FALSE)";

  private static final SimpleDateFormat dateFormat =
      new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

  private static final long ONE_DAY_MILLIS = 24 * 60 * 60 * 1000L;

  // Initial checkpoints will have timestamps 24 hours in the past,
  // because Documentum timestamps are local server time.
  private static final String YESTERDAY = dateFormat.format(
      new Date(System.currentTimeMillis() - ONE_DAY_MILLIS));

  private final IDfClientX dmClientX;
  private List<String> startPaths;
  private List<String> documentTypes;
  private CopyOnWriteArrayList<String> validatedStartPaths =
      new CopyOnWriteArrayList<String>();
  private CopyOnWriteArrayList<String> validatedDocumentTypes =
      new CopyOnWriteArrayList<String>();

  // The object attributes that should not be supplied as metadata.
  private Set<String> excludedAttributes;

  private DocIdEncoder docIdEncoder;
  private Config config;
  private IDfSessionManager dmSessionManager;
  private String docbase;
  private String displayUrl;
  private String globalNamespace;
  private String localNamespace;
  private String windowsDomain;
  private boolean pushLocalGroupsOnly;
  private int maxHtmlSize;
  private String cabinetWhereCondition;
  private CaseSensitivityType caseSensitivityType;

  /* Cache to store all types */
  private final Map<String, IDfType> superTypeCache =
      new HashMap<String, IDfType>();

  /** "The DQL function that returns the time in the server timezone.*/
  @VisibleForTesting String dateToStringFunction;

  @VisibleForTesting Checkpoint modifiedAclsCheckpoint = new Checkpoint();
  @VisibleForTesting Checkpoint modifiedDocumentsCheckpoint = new Checkpoint();
  @VisibleForTesting Checkpoint modifiedGroupsCheckpoint = new Checkpoint();
  @VisibleForTesting Checkpoint modifiedPermissionsCheckpoint =
      new Checkpoint();

  public enum CaseSensitivityType {
    EVERYTHING_CASE_SENSITIVE("everything-case-sensitive"),
    EVERYTHING_CASE_INSENSITIVE("everything-case-insensitive");

    private final String tag;

    private CaseSensitivityType(String tag) {
      this.tag = tag;
    }

    @Override
    public String toString() {
      return tag;
    }
  }

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

  /**
   * This implementation adds a {@link #getInputStream} method that
   * shares the buffer with this output stream. The input stream
   * cannot be obtained until the output stream is closed.
   */
  private static class SharedByteArrayOutputStream
      extends ByteArrayOutputStream {
    public SharedByteArrayOutputStream() {
      super();
    }

    public SharedByteArrayOutputStream(int size) {
      super(size);
    }

    /** Is this output stream open? */
    private boolean isOpen = true;

    /** Marks this output stream as closed. */
    @Override
    public void close() throws IOException {
      isOpen = false;
      super.close();
    }

    /**
     * Gets a <code>ByteArrayInputStream</code> that shares the
     * output buffer, without copying it.
     *
     * @return a <code>ByteArrayInputStream</code>
     * @throws IOException if the output stream is open
     */
    public ByteArrayInputStream getInputStream() throws IOException {
      if (isOpen) {
        throw new IOException("Output stream is open.");
      }
      return new ByteArrayInputStream(buf, 0, count);
    }
  }

  // Returns a DocId of a path with optional name to append.
  @VisibleForTesting
  static DocId docIdFromPath(String path, String name) {
    if (Strings.isNullOrEmpty(name)) {
      return docIdFromPath(path);
    } else if (path.endsWith("/")) {
      return docIdFromPath(path + name);
    } else {
      return docIdFromPath(path + "/" + name);
    }
  }
  
  // Strip leading and trailing slashes so our DocIds show up
  // as children of the baseDocUrl.
  @VisibleForTesting
  static DocId docIdFromPath(String path) {
    // Split checks to handle root, "/", which both starts and ends with '/'.
    if (path.startsWith("/")) {
      path = path.substring(1);
    }
    if (path.endsWith("/")) {
      path = path.substring(0, path.length() - 1);
    }
    return new DocId(path);
  }

  // Restore the leading slash, so we have a valid Documentum path.
  @VisibleForTesting
  static String docIdToPath(DocId docId) {
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
    config.addKey("documentum.displayUrlPattern", null);
    config.addKey("documentum.src", null);
    config.addKey("documentum.src.separator", ",");
    config.addKey("documentum.documentTypes", "dm_document");
    config.addKey("adaptor.namespace", Principal.DEFAULT_NAMESPACE);
    config.addKey("documentum.windowsDomain", "");
    config.addKey("documentum.pushLocalGroupsOnly", "false");
    config.addKey("documentum.maxHtmlSize", "1000");
    config.addKey("adaptor.caseSensitivityType",
        "everything-case-sensitive");
    // TODO(bmj): Do the system cabinet names need to be localizable?
    config.addKey("documentum.cabinetWhereCondition", "object_name NOT IN "
        + "('Integration', 'Resources', 'System', 'Temp', 'Templates') AND "
        + "object_name NOT IN (SELECT r_install_owner FROM dm_server_config) "
        + "AND object_name NOT IN (SELECT owner_name FROM dm_docbase_config)");
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
    displayUrl = config.getValue("documentum.displayUrlPattern");
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
    String separator = config.getValue("documentum.src.separator");
    logger.log(Level.CONFIG, "documentum.src.separator: {0}", separator);
    startPaths = parseStartPaths(src, separator);
    logger.log(Level.CONFIG, "start paths: {0}", startPaths);
    String types = config.getValue("documentum.documentTypes");
    logger.log(Level.CONFIG, "documentum.documentTypes: {0}", types);
    documentTypes = ImmutableList.copyOf(Splitter.on(',').trimResults()
        .omitEmptyStrings().split(types));
    logger.log(Level.CONFIG, "document types: {0}", documentTypes);
    try {
      maxHtmlSize = Math.max(0, 
          Integer.parseInt(config.getValue("documentum.maxHtmlSize").trim()));
      logger.log(Level.CONFIG, "documentum.maxHtmlSize: {0}", maxHtmlSize);
    } catch (NumberFormatException e) {
      throw new InvalidConfigurationException(
          "documentum.maxHtmlSize must be a positive integer.", e);
    }
    if (config.getValue("adaptor.caseSensitivityType").equals(
        CaseSensitivityType.EVERYTHING_CASE_INSENSITIVE.toString())) {
      caseSensitivityType = CaseSensitivityType.EVERYTHING_CASE_INSENSITIVE;
    } else {
      caseSensitivityType = CaseSensitivityType.EVERYTHING_CASE_SENSITIVE;
    }
    logger.log(Level.CONFIG, "adaptor.caseSensitivityType: {0}",
        caseSensitivityType);
    cabinetWhereCondition =
        config.getValue("documentum.cabinetWhereCondition");
    logger.log(Level.CONFIG, "documentum.cabinetWhereCondition: {0}", 
        cabinetWhereCondition);
    String excludedAttrs = config.getValue("documentum.excludedAttributes");
    excludedAttributes = ImmutableSet.copyOf(Splitter.on(",")
        .trimResults().omitEmptyStrings().split(excludedAttrs));
    logger.log(Level.CONFIG, "documentum.excludedAttributes: {0}",
        excludedAttrs);

    dmSessionManager = initDfc(context);
    IDfSession dmSession = dmSessionManager.getSession(docbase);
    dateToStringFunction = dmSession.getServerVersion().matches("[456]\\..*")
        ? "DATETOSTRING" : "DATETOSTRING_LOCAL";
    try {
      validateStartPaths(dmSession);
      validateDocumentTypes(dmSession);
    } finally {
      dmSessionManager.release(dmSession);
    }
    if (validatedStartPaths.isEmpty()) {
      throw new IllegalStateException(
         "Failed to validate documentum.src paths.");
    }
    context.setPollingIncrementalLister(this);
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
    if (Strings.isNullOrEmpty(config
        .getValue("documentum.displayUrlPattern"))) {
      throw new InvalidConfigurationException(
          "documentum.displayUrlPattern is required");
    } else {
      String pattern = config.getValue("documentum.displayUrlPattern");
      if (!(pattern.contains("{0}") || pattern.contains("{1}"))) {
        throw new InvalidConfigurationException("documentum.displayUrlPattern "
            + "must include the object ID as substitution parameter {0} "
            + "and/or the object path as substitution parameter {1}");
      }
      try {
        new URI(MessageFormat.format(pattern, "0", "/test"));
      } catch (URISyntaxException e) {
        throw new InvalidConfigurationException(
            "documentum.displayUrlPattern does not produce valid URLs", e);
      }
    }
    if (Strings.isNullOrEmpty(config.getValue("documentum.src"))) {
      throw new InvalidConfigurationException(
          "documentum.src is required");
    }
    if (Strings.isNullOrEmpty(config.getValue("documentum.documentTypes"))) {
      throw new InvalidConfigurationException(
          "documentum.documentTypes is required");
    }
  }

  @VisibleForTesting
  static List<String> parseStartPaths(String paths, String separator) {
    if (separator.isEmpty()) {
      return ImmutableList.of(paths);
    } else {
      return ImmutableList.copyOf(Splitter.on(separator)
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
      if (documentumFolderPath.equals("/")) {
        validStartPaths.add(documentumFolderPath);
        continue;
      }
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

  private void validateDocumentTypes(IDfSession dmSession) {
    List<String> validTypes = new ArrayList<String>(documentTypes.size());
    for (String typeName : documentTypes) {
      logger.log(Level.INFO, "Validating document type {0}", typeName);
      try {
        IDfType typeObj = dmSession.getType(typeName);
        if (typeObj.isTypeOf("dm_folder")) {
          logger.log(Level.WARNING,
              "Ignoring {0} which is a subtype of dm_folder", typeName);
        } else if (typeObj.isTypeOf("dm_sysobject")) {
          validTypes.add(typeName);
        } else {
          logger.log(Level.WARNING, "Invalid document type {0}", typeName);
        }
      } catch (DfException e) {
        logger.log(Level.WARNING, "Error validating document type {0}: {1}",
            new Object[] {typeName, e});
      }
    }

    if (validTypes.isEmpty()) {
      logger.log(Level.SEVERE,
          "No valid document types, at least one is required.");
    }
    validatedDocumentTypes.addAllAbsent(validTypes);
  }

  @VisibleForTesting
  List<String> getStartPaths() {
    return Collections.unmodifiableList(startPaths);
  }

  @VisibleForTesting
  List<String> getValidatedStartPaths() {
    return Collections.unmodifiableList(validatedStartPaths);
  }

  @VisibleForTesting
  List<String> getValidatedDocumentTypes() {
    return Collections.unmodifiableList(validatedDocumentTypes);
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
      validateDocumentTypes(dmSession);
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
        pusher.pushNamedResources(new DocumentumAcls(dmClientX, dmSession,
            principals, caseSensitivityType).getAcls());
      } catch (DfException e) {
        savedException = e;
      }
      try {
        pusher.pushGroupDefinitions(getGroups(dmSession, principals),
            caseSensitivityType
            == CaseSensitivityType.EVERYTHING_CASE_SENSITIVE);
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

  /**
   * Returns a map of groups and their members.
   *
   * DQL queries that return repeating attributes (in our case,
   * users_names and groups_names) do not work properly on a DB2
   * back-end. We use ENABLE(ROW_BASED) to explode the repeating
   * attributes across several rows.
   */
  private Map<GroupPrincipal, Collection<Principal>> getGroups(
      IDfSession session, Principals principals) throws DfException {
    String queryStr = makeGroupsQuery(null);
    logger.log(Level.FINER, "Get Groups Query: {0}", queryStr);
    IDfQuery query = dmClientX.getQuery();
    query.setDQL(queryStr);
    IDfCollection result = query.execute(session, IDfQuery.DF_EXECREAD_QUERY);
    try {
      ImmutableMap.Builder<GroupPrincipal, Collection<Principal>> groups =
          ImmutableMap.builder();
      ImmutableSet.Builder<Principal> members = null;
      String groupName = "";
      while (result.next()) {
        if (!groupName.equals(result.getString("group_name"))) {
          // We have transitioned to a new group.
          addGroup(groupName, groups, members, principals);
          members = ImmutableSet.builder();
          groupName = result.getString("group_name");
          logger.log(Level.FINE, "Found Group: {0}", groupName);
        }
        addMemberPrincipal(members, principals,
            result.getString("users_names"), false);
        addMemberPrincipal(members, principals, 
            result.getString("groups_names"), true);
      }
      addGroup(groupName, groups, members, principals);

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
  private void addGroup(String groupName,
      ImmutableMap.Builder<GroupPrincipal, Collection<Principal>> groupsBuilder,
      ImmutableSet.Builder<Principal> membersBuilder, Principals principals)
      throws DfException {
    if (membersBuilder == null) {
      return;
    }
    String principalName = principals.getPrincipalName(groupName);
    if (principalName == null) {
      return;
    }
    GroupPrincipal groupPrincipal = (GroupPrincipal)
        principals.getPrincipal(groupName, principalName, true);
    ImmutableSet<Principal> members = membersBuilder.build();
    groupsBuilder.put(groupPrincipal, members);
    logger.log(Level.FINEST, "Pushing Group {0}: {1}",
        new Object[] { principalName, members });
  }

  /** Adds a Principal for a user or group to the set of members. */
  private void addMemberPrincipal(ImmutableSet.Builder<Principal> members,
     Principals principals, String memberName, boolean isGroup)
     throws DfException {
   if (memberName != null) {
      String principalName = principals.getPrincipalName(memberName);
      if (principalName != null) {
        members.add(
            principals.getPrincipal(memberName, principalName, isGroup));
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

  /** Builds the DQL query to retrieve the groups. */
  private String makeGroupsQuery(Checkpoint checkpoint) {
    StringBuilder query = new StringBuilder();
    query.append("SELECT r_object_id, group_name, groups_names, users_names");
    if (checkpoint == null) {
      query.append(" FROM dm_group");
    } else {
      query.append(", r_modify_date, ")
          .append(dateToStringFunction)
          .append("(r_modify_date, 'yyyy-mm-dd hh:mi:ss') ")
          .append("AS r_modify_date_str FROM dm_group WHERE ")
          .append(MessageFormat.format(
              "((r_modify_date = DATE(''{0}'',''yyyy-mm-dd hh:mi:ss'') AND "
              + "r_object_id > ''{1}'') OR (r_modify_date > DATE(''{0}'',"
              + "''yyyy-mm-dd hh:mi:ss'')))",
              checkpoint.getLastModified(), checkpoint.getObjectId()));
    }
    if (pushLocalGroupsOnly) {
      query.append((checkpoint == null) ? " WHERE " : " AND ")
          .append("(group_source IS NULL OR group_source <> 'LDAP')");
    }
    query.append(" ORDER BY group_name ENABLE(ROW_BASED)");
    return query.toString();
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
        validateDocumentTypes(dmSession);
        modifiedDocumentsCheckpoint = pushDocumentUpdates(pusher, dmSession,
            modifiedDocumentsCheckpoint);
      } catch (DfException e) {
        savedException = e;
      }

      Principals principals = new Principals(dmSession, localNamespace,
          globalNamespace, windowsDomain);
      try {
        modifiedAclsCheckpoint = pushAclUpdates(pusher, dmSession,
          principals, modifiedAclsCheckpoint);
      } catch (DfException e) {
        savedException = e;
      }

      try {
        modifiedGroupsCheckpoint = pushGroupUpdates(pusher, dmSession,
            principals, modifiedGroupsCheckpoint);
      } catch (DfException e) {
        savedException = e;
      }

      try {
        modifiedPermissionsCheckpoint = pushPermissionsUpdates(pusher,
            dmSession, modifiedPermissionsCheckpoint);
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
  private Checkpoint pushAclUpdates(DocIdPusher pusher, IDfSession session,
      Principals principals, Checkpoint checkpoint)
      throws DfException, IOException, InterruptedException {
    DocumentumAcls dctmAcls =
        new DocumentumAcls(dmClientX, session, principals, caseSensitivityType);
    Map<DocId, Acl> aclMap = dctmAcls.getUpdateAcls(checkpoint);
    pusher.pushNamedResources(aclMap);
    return dctmAcls.getUpdateAclsCheckpoint();
  }

  /**
   * Push Document updates to GSA.
   */
  private Checkpoint pushDocumentUpdates(DocIdPusher pusher, IDfSession session,
      Checkpoint checkpoint)
      throws DfException, IOException, InterruptedException {
    String queryStr = makeUpdatedDocsQuery(checkpoint);
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
        String name = result.getString("object_name");
        addUpdatedDocIds(builder, session, objectId, name);
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
   * Push Document ACL link updates to GSA.
   */
  private Checkpoint pushPermissionsUpdates(DocIdPusher pusher,
      IDfSession session, Checkpoint checkpoint) throws DfException,
      InterruptedException {
    String queryStr = makeUpdatedPermissionsQuery(checkpoint);
    logger.log(Level.FINER, "Modified permissions query: {0}", queryStr);
    IDfQuery query = dmClientX.getQuery();
    query.setDQL(queryStr);
    IDfCollection result = query.execute(session, IDfQuery.DF_EXECREAD_QUERY);
    try {
      HashSet<String> chronicleIds = new HashSet<>();
      String eventDate = checkpoint.getLastModified();
      String eventId = checkpoint.getObjectId();
      ImmutableList.Builder<Record> builder = ImmutableList.builder();
      while (result.next()) {
        eventDate = result.getString("time_stamp_utc_str");
        eventId = result.getString("r_object_id");
        String objectId = result.getString("audited_obj_id");
        String chronicleId = result.getString("chronicle_id");
        String objectName = result.getString("object_name");

        if (chronicleIds.contains(chronicleId)) {
          logger.log(Level.FINEST,
              "Skipping already processed event {0} for chronicle ID {1}",
              new String[] {eventId, chronicleId});
          continue;
        }
        logger.log(Level.FINER, "Processing permission changes "
            + "time_stamp_utc: {0}, "
            + "r_object_id: {1}, "
            + "audited_obj_id: {2}, "
            + "chronicle_id: {3}",
            new String[] {eventDate, eventId, objectId, chronicleId});

        addUpdatedDocIds(builder, session, objectId, objectName);
        chronicleIds.add(chronicleId);
      }
      List<Record> records = builder.build();
      logger.log(Level.FINER, "DocumentumAdaptor Modified ACL Links: {0}",
          records);
      pusher.pushRecords(records);
      return new Checkpoint(eventDate, eventId);
    } finally {
      result.close();
    }
  }

  /**
   * A document can reside under multiple folder paths.
   * Only push those paths that are under our start paths.
   *
   * @param builder builder for list of DocIds
   * @param objectId the ID of a Documentum object
   * @param name the document name to append to the folder
   *    paths for a document, or null for a folder
   */
  private void addUpdatedDocIds(ImmutableList.Builder<Record> builder,
      IDfSession session, String objectId, String name) throws DfException {
    IDfEnumeration enumPaths = session.getObjectPaths(new DfId(objectId));
    while (enumPaths.hasMoreElements()) {
      IDfObjectPath objPath = (IDfObjectPath) enumPaths.nextElement();
      String path = objPath.getFullPath();
      DocId docId = docIdFromPath(path, name);
      if (isUnderStartPath(docIdToPath(docId), validatedStartPaths)) {
        builder.add(new Record.Builder(docId)
            .setCrawlImmediately(true).build());
      }
    }
  }

  private String makeUpdatedDocsQuery(Checkpoint checkpoint) {
    StringBuilder query = new StringBuilder();
    query.append("SELECT object_name, r_object_id, r_object_type, ")
        .append("i_folder_id, r_modify_date, ")
        .append(dateToStringFunction)
        .append("(r_modify_date, 'yyyy-mm-dd hh:mi:ss') ")
        .append("AS r_modify_date_str FROM dm_sysobject ")
        // Limit the returned object types to types specified in
        // documentum.documentTypes config property or dm_folder.
        .append("WHERE (");
    for (String typeName : validatedDocumentTypes) {
      query.append("TYPE(").append(typeName).append(") OR ");
    }
    query.append("TYPE(dm_folder)) AND ")
       .append(MessageFormat.format(
            "((r_modify_date = DATE(''{0}'',''yyyy-mm-dd hh:mi:ss'') AND "
            + "r_object_id > ''{1}'') OR (r_modify_date > DATE(''{0}'',"
            + "''yyyy-mm-dd hh:mi:ss'')))",
            checkpoint.getLastModified(), checkpoint.getObjectId()));

    // Limit our search to modified docs under a start path.
    query.append(" AND (FOLDER('");
    Joiner.on("',descend) OR FOLDER('").appendTo(query, validatedStartPaths);
    query.append("',descend)) ORDER BY r_modify_date, r_object_id");
    return query.toString();
  }

  private String makeUpdatedPermissionsQuery(Checkpoint checkpoint) {
    StringBuilder query = new StringBuilder();
    query.append("SELECT ")
        .append(dateToStringFunction)
        .append("(a.time_stamp_utc, 'yyyy-mm-dd hh:mi:ss') ")
        .append("AS time_stamp_utc_str, ")
        .append("a.r_object_id, a.audited_obj_id, a.chronicle_id, ")
        .append("s.object_name FROM dm_sysobject s, dm_audittrail a ")
        .append("WHERE a.audited_obj_id = s.r_object_id ")
        .append("AND (FOLDER('");
    Joiner.on("',descend) OR FOLDER('").appendTo(query, validatedStartPaths);
    query.append("',descend)) ")
        .append("AND a.event_name = 'dm_save' AND a.attribute_list ")
        .append("LIKE 'acl_name=%' AND ")
        .append(MessageFormat.format("((a.time_stamp_utc = DATE(''{0}'', "
            + "''yyyy-mm-dd hh:mi:ss'') AND (a.r_object_id > ''{1}'')) "
            + "OR (a.time_stamp_utc > DATE(''{0}'', ''yyyy-mm-dd hh:mi:ss''))) "
            + "ORDER BY a.time_stamp_utc, a.r_object_id",
            checkpoint.getLastModified(), checkpoint.getObjectId()));
    return query.toString();
  }

  /**
   * Push Group updates to GSA.
   */
  private Checkpoint pushGroupUpdates(DocIdPusher pusher, IDfSession session,
      Principals principals, Checkpoint checkpoint)
      throws DfException, IOException, InterruptedException {
    String queryStr = makeGroupsQuery(checkpoint);
    logger.log(Level.FINER, "Modified Groups Query: {0}", queryStr);
    IDfQuery query = dmClientX.getQuery();
    query.setDQL(queryStr);
    IDfCollection result = query.execute(session, IDfQuery.DF_EXECREAD_QUERY);
    try {
      ImmutableMap.Builder<GroupPrincipal, Collection<Principal>> groups =
          ImmutableMap.builder();
      ImmutableSet.Builder<Principal> members = null;
      String groupName = "";
      String lastModified = checkpoint.getLastModified();
      String objectId = checkpoint.getObjectId();
      while (result.next()) {
        if (!groupName.equals(result.getString("group_name"))) {
          // We have transitioned to a new group.
          addGroup(groupName, groups, members, principals);
          members = ImmutableSet.builder();
          groupName = result.getString("group_name");
          lastModified = result.getString("r_modify_date_str");
          objectId = result.getString("r_object_id");
          logger.log(Level.FINE, "Found Group: {0}", groupName);
        }
        addMemberPrincipal(members, principals,
            result.getString("users_names"), false);
        addMemberPrincipal(members, principals, 
            result.getString("groups_names"), true);
      }
      addGroup(groupName, groups, members, principals);
      pusher.pushGroupDefinitions(groups.build(),
          caseSensitivityType == CaseSensitivityType.EVERYTHING_CASE_SENSITIVE);
      return new Checkpoint(lastModified, objectId);
    } finally {
      result.close();
    }
  }

  /** Gives the bytes of a document referenced with id. 
   *
   * @throws IOException if a Documentum error occurs
   */
  @Override
  public void getDocContent(Request req, Response resp) throws IOException {
    DocId id = req.getDocId();
    logger.log(Level.FINER, "Get content for id: {0}", id);

    String path = docIdToPath(id);
    if (!isUnderStartPath(path, validatedStartPaths)) {
      resp.respondNotFound();
      return;
    }

    IDfSession dmSession = null;
    try {
      dmSession = dmSessionManager.getSession(docbase);

      // Special root path "/" means return all cabinets.
      if (path.equals("/")) {
        getRootContent(resp, dmSession, id);
        return;
      }

      IDfPersistentObject dmPersObj;
      if (path.matches(".*:\\p{XDigit}{16}")) {
        String objId = path.substring(path.length() - 16);
        logger.log(Level.FINER, "VDoc Child Object Id: {0}", objId);
        dmPersObj = dmSession.getObject(new DfId(objId));
        // Check for a false positive regex match.
        if (dmPersObj == null) {
          dmPersObj = dmSession.getObjectByPath(path);
        }
      } else {
        dmPersObj = dmSession.getObjectByPath(path);
      }

      if (dmPersObj == null) {
        logger.log(Level.FINER, "Not found: {0}", id);
        resp.respondNotFound();
        return;
      }

      IDfId dmObjId = dmPersObj.getObjectId();
      IDfType type = dmPersObj.getType();
      logger.log(Level.FINER, "Object Id: {0}; Type: {1}",
          new Object[] {dmObjId, type.getName()});

      Date lastCrawled = req.getLastAccessTime();
      if (lastCrawled != null) {
        Date lastModified = dmPersObj.getTime("r_modify_date").getDate();
        if (lastModified != null) {
          // To avoid issues with time zones, we only count an object as
          // unmodified if its last modified time is more than a day before
          // the last crawl time.
          if (lastModified.before(
              new Date(lastCrawled.getTime() - ONE_DAY_MILLIS))) {
            logger.log(Level.FINER, "Not Modified: {0}", dmObjId);
            resp.respondNotModified();
            return;
          }
        }
      }

      if (isValidatedDocumentType(type)) {
        getDocumentContent(resp, (IDfSysObject) dmPersObj, id);
      } else if (type.isTypeOf("dm_folder")) {
        getFolderContent(resp, (IDfFolder) dmPersObj, id);
      } else {
        logger.log(Level.WARNING, "Unsupported type: {0}", type);
        resp.respondNotFound();
      }
    } catch (DfException e) {
      throw new IOException("Error getting content:", e);
    } catch (URISyntaxException e) {
      throw new IOException("Error getting URI:", e);
    } finally {
      if (dmSession != null) {
        dmSessionManager.release(dmSession);
      }
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
      if (startPath.equals("/")) {
        return true;
      }
      if (startPath.equals(path) || path.startsWith(startPath + "/")) {
        return true;
      }
    }
    return false;
  }

  private boolean isValidatedDocumentType(IDfType type) throws DfException {
    for (String typeName : validatedDocumentTypes) {
      if (type.isTypeOf(typeName)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Returns all the docbase's cabinets as links in a generated HTML document
   * and as external links.
   */
  private void getRootContent(Response resp, IDfSession session, DocId id)
      throws DfException, IOException {
    String queryStr = MessageFormat.format(
       "SELECT r_folder_path FROM dm_cabinet{0,choice,0#|0< WHERE {1}}",
        cabinetWhereCondition.length(), cabinetWhereCondition);
    // Don't use MessageFormat syntax for this log message for testing purposes.
    logger.log(Level.FINER, "Get All Cabinets Query: " + queryStr);
    IDfQuery query = dmClientX.getQuery();
    query.setDQL(queryStr);
    IDfCollection result = query.execute(session, IDfQuery.DF_EXECREAD_QUERY);
    try {
      // Large Documentum deployments can have tens or hundreds of thousands
      // of cabinets. The GSA truncates large HTML documents at 2.5MB, so return
      // the first maxHtmlLinks worth as HTML content and the rest as external
      // anchors. But we cannot start writing the HTML content to the response
      // until after we add all the external anchor metadata. So spool the HTML
      // for now and copy it to the response later.
      SharedByteArrayOutputStream htmlOut = new SharedByteArrayOutputStream();
      Writer writer = new OutputStreamWriter(htmlOut, CHARSET);
      try (HtmlResponseWriter htmlWriter =
          new HtmlResponseWriter(writer, docIdEncoder, Locale.ENGLISH)) {
        htmlWriter.start(id, "/");
        for (int i = 0; i < maxHtmlSize && result.next(); i++) {
          String cabinet = result.getString("r_folder_path");
          logger.log(Level.FINER, "Cabinet: {0}", cabinet);
          DocId docid = docIdFromPath(cabinet);
          htmlWriter.addLink(docid, docid.getUniqueId());
        }
        htmlWriter.finish();
      }

      // Add the remaining cabinets as external anchors.
      while (result.next()) {
        String cabinet = result.getString("r_folder_path");
        logger.log(Level.FINER, "Cabinet: {0}", cabinet);
        DocId docid = docIdFromPath(cabinet);
        resp.addAnchor(docIdEncoder.encodeDocId(docid), docid.getUniqueId());
      }

      // Finally, write out the generated HTML links as content.
      resp.setContentType("text/html; charset=" + CHARSET.name());
      IOHelper.copyStream(htmlOut.getInputStream(), resp.getOutputStream());
    } finally {
      result.close();
    }
  }

  /** Copies the Documentum document content into the response.
   * @throws URISyntaxException */
  private void getDocumentContent(Response resp, IDfSysObject dmSysbObj,
      DocId id) throws DfException, IOException, URISyntaxException {
    getACL(resp, dmSysbObj, id);
    // Include document attributes as metadata.
    getMetadata(resp, dmSysbObj, id);

    // If it is a virtual document, include links to the child documents.
    if (dmSysbObj.isVirtualDocument()) {
      getVdocChildLinks(resp, dmSysbObj, id);
    }

    // Return the content.
    String contentType = dmSysbObj.getContentType();
    logger.log(Level.FINER, "Content Type: {0}", contentType);
    resp.setContentType(contentType);
    resp.setDisplayUrl(new URI(MessageFormat.format(displayUrl,
        dmSysbObj.getObjectId(), docIdToPath(id))));
    try (InputStream inStream = dmSysbObj.getContent()) {
      IOHelper.copyStream(inStream, resp.getOutputStream());
    }
  }

  /** Supplies the document ACL in the response.
   * @throws DfException */
  private void getACL(Response resp, IDfSysObject dmSysbObj, DocId id)
      throws DfException {
    String aclId = dmSysbObj.getACL().getObjectId().toString();
    logger.log(Level.FINER, "ACL for id {0} is {1}", new Object[] {id, aclId});
    resp.setAcl(new Acl.Builder().setInheritFrom(new DocId(aclId)).build());
  }

  /** Supplies the document attributes as metadata in the response. */
  private void getMetadata(Response resp, IDfSysObject dmSysbObj, DocId id)
      throws DfException, IOException {
    Set<String> attributeNames = getAttributeNames(dmSysbObj);
    for (String name : attributeNames) {
      if (!excludedAttributes.contains(name)) {
        if ("r_object_id".equals(name)) {
          String value = dmSysbObj.getObjectId().toString();
          resp.addMetadata(name, value);
          continue;
        } else if ("r_object_type".equals(name)) {
          // Retrieves object type and its super type(s).
          for (IDfType type = dmSysbObj.getType();
               type != null;
               type = getSuperType(type)) {
            resp.addMetadata(name, type.getName());
          }
          continue;
        }

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
    builder.add("r_object_id");
    while (e.hasMoreElements()) {
      builder.add(e.nextElement().getName());
    }
    return builder.build();
  }

  /**
   * Return the supertype for the supplied type. Caches result to
   * avoid frequent round-trips to server.
   *
   * @return superType for supplied type, or null if type is root type.
   */
  private IDfType getSuperType(IDfType type) throws DfException {
    if (type == null) {
      return null;
    }
    String typeName = type.getName();
    if (superTypeCache.containsKey(typeName)) {
      return superTypeCache.get(typeName);
    } else {
      IDfType superType = type.getSuperType();
      superTypeCache.put(typeName, superType);
      return superType;
    }
  }

  /** Supplies VDoc children as external link metadata in the response. */
  private void getVdocChildLinks(Response resp, IDfSysObject dmSysbObj,
      DocId id) throws DfException, IOException {
    IDfVirtualDocument vDoc = dmSysbObj.asVirtualDocument("CURRENT", false);
    IDfVirtualDocumentNode root = vDoc.getRootNode();
    int count = root.getChildCount();
    for (int i = 0; i < count; i++) {
      IDfSysObject child = root.getChild(i).getSelectedObject();
      String objId = child.getString("r_object_id");
      String objName = child.getString("object_name");
      logger.log(Level.FINER, "VDoc Child Object Id: {0}; Name: {1}",
          new Object[] {objId, objName});
      DocId childDocId = docIdFromPath(docIdToPath(id), objName + ":" + objId);
      logger.log(Level.FINER, "VDoc Child Object DocId: {0}",
          childDocId.toString());
      resp.addAnchor(docIdEncoder.encodeDocId(childDocId), objName);
    }
  }

  /** Returns the Folder's contents as links in a generated HTML document. */
  private void getFolderContent(Response resp, IDfFolder dmFolder, DocId id)
      throws DfException, IOException {
    getACL(resp, dmFolder, id);
    // Include folder attributes as metadata.
    getMetadata(resp, dmFolder, id);

    logger.log(Level.FINER, "Listing contents of folder: {0} ",
        dmFolder.getObjectName());
    IDfCollection dmCollection =
        dmFolder.getContents("r_object_id, object_name");

    // TODO(bmj): Use maxHtmlSize in getFolderContent.
    try (HtmlResponseWriter htmlWriter = createHtmlResponseWriter(resp)) {
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

  private HtmlResponseWriter createHtmlResponseWriter(Response response)
      throws IOException {
    response.setContentType("text/html; charset=" + CHARSET.name());
    Writer writer = new OutputStreamWriter(response.getOutputStream(), CHARSET);
    // TODO(ejona): Get locale from request.
    return new HtmlResponseWriter(writer, docIdEncoder, Locale.ENGLISH);
  }

  /**
   * Establishes connection DFC.
   * 
   * @param context the Adaptor Context
   * @return a new DFC session manager for the configured username and
   *         docbaseName
   * @throws DfException if error in getting local client or error in setting 
   *         repository identity, or error in getting session, or error in 
   *         getting server version.
   */
  private IDfSessionManager initDfc(AdaptorContext context) throws DfException {
    IDfSessionManager dmSessionManager =
        dmClientX.getLocalClient().newSessionManager();

    Config config = context.getConfig();
    String username = config.getValue("documentum.username");
    String docbaseName = config.getValue("documentum.docbaseName");
    logger.log(Level.CONFIG, "documentum.username: {0}", username);
    logger.log(Level.CONFIG, "documentum.docbaseName: {0}", docbaseName);

    IDfLoginInfo dmLoginInfo = dmClientX.getLoginInfo();
    dmLoginInfo.setUser(username);
    dmLoginInfo.setPassword(context.getSensitiveValueDecoder()
        .decodeValue(config.getValue("documentum.password")));
    dmSessionManager.setIdentity(docbaseName, dmLoginInfo);

    IDfSession dmSession = dmSessionManager.getSession(docbaseName);
    try {
      logger.log(Level.INFO, "DFC {0} connected to Content Server {1}",
          new Object[]
              { dmClientX.getDFCVersion(), dmSession.getServerVersion() });
      logger.log(Level.INFO, "Created a new session for the docbase {0}",
          docbaseName);
    } finally {
      logger.log(Level.INFO, "Releasing dfc session for {0}", docbaseName);
      dmSessionManager.release(dmSession);
    }

    return dmSessionManager;
  }
}
