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

import com.google.enterprise.adaptor.AbstractAdaptor;
import com.google.enterprise.adaptor.AdaptorContext;
import com.google.enterprise.adaptor.Config;
import com.google.enterprise.adaptor.DocIdPusher;
import com.google.enterprise.adaptor.InvalidConfigurationException;
import com.google.enterprise.adaptor.Request;
import com.google.enterprise.adaptor.Response;
import com.google.common.base.Strings;

import com.documentum.com.DfClientX;
import com.documentum.com.IDfClientX;
import com.documentum.fc.client.IDfSession;
import com.documentum.fc.client.IDfSessionManager;
import com.documentum.fc.common.DfException;
import com.documentum.fc.common.IDfLoginInfo;

import java.util.logging.Logger;
import java.util.logging.Level;

/** Adaptor to feed Documentum repository content into a 
 *  Google Search Appliance.
 */
public class DocumentumAdaptor extends AbstractAdaptor {
  private static Logger logger =
      Logger.getLogger(DocumentumAdaptor.class.getName());

  private IDfSessionManager idfSessionManager;
  private IDfSession idfSession;

  public static void main(String[] args) {
    AbstractAdaptor.main(new DocumentumAdaptor(), args);
  }

  @Override
  public void initConfig(Config config) {
    config.addKey("documentum.username", null);
    config.addKey("documentum.password", null);
    config.addKey("documentum.docbaseName", null);
  }

  @Override
  public void init(AdaptorContext context) throws Exception {
    Config config = context.getConfig();
    validateConfig(config);
    initDfc(config);
  }

  /** Get all doc ids from documentum repository. */
  @Override
  public void getDocIds(DocIdPusher pusher) {
  }

  /** Gives the bytes of a document referenced with id. */
  @Override
  public void getDocContent(Request req, Response resp) {
  }

  /**
   * {@inheritDoc}
   *
   * Close DFC session.
   */
  @Override
  public void destroy() {
    if (idfSessionManager != null) {
      try {
        logger.log(Level.INFO, "Releasing dfc session for {0}",
            idfSession.getDocbaseName());
        idfSessionManager.release(idfSession);
      } catch (DfException e) {
        logger.log(Level.SEVERE, "Error closing dfc session");
      }
    }
  }

  private void validateConfig(Config config) {
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
  }

  private void initDfc(Config config) throws DfException {
    IDfClientX clientX = new DfClientX();
    this.idfSessionManager = clientX.getLocalClient().newSessionManager();

    IDfLoginInfo dctmLoginInfo = clientX.getLoginInfo();
    String userName = config.getValue("documentum.username");
    String password = config.getValue("documentum.password");
    String docbaseName = config.getValue("documentum.docbaseName");
    dctmLoginInfo.setUser(userName);
    dctmLoginInfo.setPassword(password);
    idfSessionManager.setIdentity(docbaseName, dctmLoginInfo);
    this.idfSession = idfSessionManager.newSession(docbaseName);
    logger.log(Level.FINE, "Session Manager set the identity for " + userName);
    logger.log(Level.INFO, "DFC " + clientX.getDFCVersion()
        + " connected to Content Server " + idfSession.getServerVersion());
    logger.log(Level.INFO, "Tested a new session for the docbase "
        + docbaseName);
  }
}
