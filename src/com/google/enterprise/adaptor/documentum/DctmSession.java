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

import com.documentum.com.DfClientX;
import com.documentum.com.IDfClientX;
import com.documentum.fc.client.IDfSession;
import com.documentum.fc.client.IDfSessionManager;
import com.documentum.fc.common.DfException;
import com.documentum.fc.common.IDfLoginInfo;
import com.google.enterprise.adaptor.Config;

import java.util.logging.Logger;

public class DctmSession implements ISession {
  private static Logger logger = Logger.getLogger(DctmSession.class.getName());

  private final IDfSession idfSession;

  public DctmSession(Config config) throws RepositoryException {
    try {
      IDfClientX clientX = new DfClientX();
      IDfSessionManager sessionManager =
          clientX.getLocalClient().newSessionManager();

      IDfLoginInfo dctmLoginInfo = clientX.getLoginInfo();
      String userName = config.getValue("dctm.username");
      dctmLoginInfo.setUser(userName);
      String userPassword = config.getValue("dctm.userpassword");
      dctmLoginInfo.setPassword(userPassword);
      String docbaseName = config.getValue("dctm.docbasename");
      sessionManager.setIdentity(docbaseName, dctmLoginInfo);
      logger.fine("Session Manager set the identity for " + userName);

      idfSession = sessionManager.newSession(docbaseName);
      logger.info("DFC " + clientX.getDFCVersion()
          + " connected to Content Server " + idfSession.getServerVersion());
      sessionManager.release(idfSession);
      logger.info("Tested a new session for the docbase " + docbaseName);
    } catch (DfException e) {
      throw new RepositoryException(e);
    }
  }

  public DctmSession(IDfSession idfSession) {
    this.idfSession = idfSession;
  }

  public String getLoginUserName() throws RepositoryException {
    try {
      return idfSession.getLoginUserName();
    } catch (DfException de) {
      throw new RepositoryException(de);
    }
  }

  public String getDocbaseName() throws RepositoryException {
    try {
      return idfSession.getDocbaseName();
    } catch (DfException de) {
      throw new RepositoryException(de);
    }
  }

  public String getServerVersion() throws RepositoryException {
    try {
      return idfSession.getServerVersion();
    } catch (DfException de) {
      throw new RepositoryException(de);
    }
  }

  public ISessionManager getSessionManager() throws RepositoryException {
    return new DctmSessionManager(idfSession.getSessionManager());
  }

  IDfSession getDfSession() {
    return idfSession;
  }
}
