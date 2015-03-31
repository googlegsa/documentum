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
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.enterprise.adaptor.AbstractAdaptor;
import com.google.enterprise.adaptor.AdaptorContext;
import com.google.enterprise.adaptor.Config;
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.DocIdEncoder;
import com.google.enterprise.adaptor.DocIdPusher;
import com.google.enterprise.adaptor.IOHelper;
import com.google.enterprise.adaptor.InvalidConfigurationException;
import com.google.enterprise.adaptor.Request;
import com.google.enterprise.adaptor.Response;

import com.documentum.com.DfClientX;
import com.documentum.com.IDfClientX;
import com.documentum.fc.client.IDfCollection;
import com.documentum.fc.client.IDfFolder;
import com.documentum.fc.client.IDfPersistentObject;
import com.documentum.fc.client.IDfSession;
import com.documentum.fc.client.IDfSessionManager;
import com.documentum.fc.client.IDfSysObject;
import com.documentum.fc.client.IDfType;
import com.documentum.fc.common.DfException;
import com.documentum.fc.common.IDfId;
import com.documentum.fc.common.IDfLoginInfo;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/** Adaptor to feed Documentum repository content into a 
 *  Google Search Appliance.
 */
public class DocumentumAdaptor extends AbstractAdaptor {
  private static Logger logger =
      Logger.getLogger(DocumentumAdaptor.class.getName());

  /** Charset used in generated HTML responses. */
  private static final Charset CHARSET = Charset.forName("UTF-8");

  private final IDfClientX dmClientX;
  private List<String> startPaths;
  private List<String> validatedStartPaths = new ArrayList<String>();

  private DocIdEncoder docIdEncoder;
  private IDfSessionManager dmSessionManager;
  private String docbase;

  public static void main(String[] args) {
    AbstractAdaptor.main(new DocumentumAdaptor(), args);
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
  }

  @Override
  public void init(AdaptorContext context) throws DfException {
    docIdEncoder = context.getDocIdEncoder();
    Config config = context.getConfig();
    validateConfig(config);
    docbase = config.getValue("documentum.docbaseName");
    String src = config.getValue("documentum.src");
    logger.log(Level.CONFIG, "documentum.src: {0}", src);
    String separatorRegex = config.getValue("documentum.separatorRegex");
    logger.log(Level.CONFIG, "documentum.separatorRegex: {0}", separatorRegex);
    startPaths = parseStartPaths(src, separatorRegex);
    logger.log(Level.CONFIG, "start paths: {0}", startPaths);
    initDfc(config);
    dmSessionManager = getDfcSessionManager(config);
    validatePaths();
    if (validatedStartPaths.isEmpty()) {
      throw new IllegalStateException(
          "Failed to validate documentum.src paths.");
    }
  }

  /** Get all doc ids from Documentum repository. 
   * @throws InterruptedException if pusher is interrupted in sending Doc Ids
   */
  @Override
  public void getDocIds(DocIdPusher pusher) throws InterruptedException {
    logger.entering("DocumentumAdaptor", "getDocIds");
    try {
      validatePaths();
    } catch (DfException e) {
      logger.log(Level.WARNING, "Error validating start paths");
    }
    ArrayList<DocId> docIds = new ArrayList<DocId>();
    for (String startPath : validatedStartPaths) {
      docIds.add(new DocId(startPath));
    }
    logger.log(Level.FINER, "DocumentumAdaptor DocIds: {0}", docIds);
    pusher.pushDocIds(docIds);
    logger.exiting("DocumentumAdaptor", "getDocIds");
  }

  @VisibleForTesting
  List<String> getStartPaths() {
    return Collections.unmodifiableList(startPaths);
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

  /** Gives the bytes of a document referenced with id. 
   * @throws IOException */
  @Override
  public void getDocContent(Request req, Response resp) throws IOException {
    // TODO: (sveldurthi) support "/" as start path, to process all cabinets.
    // TODO: (sveldurthi) validate the requested doc id is in start paths,
    //       if not send a 404.
    getDocContentHelper(req, resp, dmSessionManager, docIdEncoder);
  }

  @VisibleForTesting
  void getDocContentHelper(Request req, Response resp,
      IDfSessionManager dmSessionManager, DocIdEncoder docIdEncoder)
      throws IOException {
    DocId id = req.getDocId();
    logger.log(Level.FINER, "Get content for id: {0}", id);

    IDfSession dmSession;
    try {
      dmSession = dmSessionManager.getSession(docbase);

      IDfPersistentObject dmPersObj =
          dmSession.getObjectByPath(id.getUniqueId());
      if (dmPersObj == null) {
        logger.log(Level.FINER, "Not found: {0}", id);
        resp.respondNotFound();
        return;
      }

      IDfId dmObjId = dmPersObj.getObjectId();
      IDfType type = dmPersObj.getType();
      logger.log(Level.FINER, "Object Id: {0}; Type: {1}",
          new Object[] {dmObjId, type.getName()});

      if (!type.isTypeOf("dm_document") && !type.isTypeOf("dm_folder")) {
        logger.log(Level.WARNING, "Unsupported type: {0}", type);
        resp.respondNotFound();
      } else if (type.isTypeOf("dm_document")) {
        IDfSysObject dmSysbObj = (IDfSysObject) dmPersObj;
        String contentType = dmSysbObj.getContentType();
        logger.log(Level.FINER, "Content Type: {0}",
            new Object[] {contentType});

        resp.setContentType(contentType);
        InputStream inStream = dmSysbObj.getContent();
        OutputStream outStream = resp.getOutputStream();
        try {
          IOHelper.copyStream(inStream, outStream);
        } finally {
          inStream.close();
        }
      } else {
        IDfFolder dmFolder = (IDfFolder) dmPersObj;
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
            DocId childDocId = new DocId(id.getUniqueId() + "/" + objName);
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
    } catch (DfException e) {
      throw new IOException("Error getting content:", e);
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

  @VisibleForTesting
  List<String> getValidatedStartPaths() {
    return validatedStartPaths;
  }

  /**
   * Validate start paths and add the valid ones to validatedStartPaths list.
   * 
   * @throws DfException if the session can't be established to the repository.
   */
  private void validatePaths() throws DfException {
    IDfSession dmSession = dmSessionManager.getSession(docbase);

    for (String documentumFolderPath : startPaths) {
      logger.log(Level.INFO, "Validating path {0}", documentumFolderPath);
      IDfSysObject obj = null;
      try {
        obj = (IDfSysObject) dmSession.getObjectByPath(documentumFolderPath);
      } catch (DfException e) {
        logger.log(Level.WARNING, "Error validating start path {0}",
            e.getMessage());
      }
      if (obj == null) {
        logger.log(Level.WARNING, "Invalid start path {0}",
            documentumFolderPath);
      } else {
        if (!validatedStartPaths.contains(documentumFolderPath)) {
          logger.log(Level.CONFIG, "Valid start path {0} id:{1}", new Object[] {
              documentumFolderPath, obj.getObjectId().toString()});
          validatedStartPaths.add(documentumFolderPath);
        }
      }
    }

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

  private HtmlResponseWriter createHtmlResponseWriter(Response response,
      DocIdEncoder docIdEncoder) throws IOException {
    response.setContentType("text/html; charset=" + CHARSET.name());
    Writer writer = new OutputStreamWriter(response.getOutputStream(), CHARSET);
    // TODO(ejona): Get locale from request.
    return new HtmlResponseWriter(writer, docIdEncoder, Locale.ENGLISH);
  }
}
