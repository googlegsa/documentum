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

import com.documentum.fc.client.DfAuthenticationException;
import com.documentum.fc.client.DfIdentityException;
import com.documentum.fc.client.DfPrincipalException;
import com.documentum.fc.client.DfServiceException;
import com.documentum.fc.client.IDfSession;
import com.documentum.fc.client.IDfSessionManager;
import com.documentum.fc.common.DfException;
import com.documentum.fc.common.IDfLoginInfo;

import java.util.logging.Level;
import java.util.logging.Logger;

public class DctmSessionManager implements ISessionManager {
  private static Logger logger = 
      Logger.getLogger(DctmSessionManager.class.getName());

  private final IDfSessionManager dfSessionManager;

  public DctmSessionManager(IDfSessionManager dfSessionManager) {
    this.dfSessionManager = dfSessionManager;
  }

  public ISession getSession(String docbase) throws RepositoryException {
    IDfSession dfSession = null;
    try {
      dfSession = dfSessionManager.getSession(docbase);
      if (logger.isLoggable(Level.FINER)) {
        IDfLoginInfo idfLoginInfo = dfSessionManager.getIdentity(docbase);
        logger.finer("Session for user: " + idfLoginInfo.getUser() + ": "
            + dfSession + " (id=" + dfSession.getSessionId() + ')');
      }
    } catch (DfIdentityException e) {
      throw new RepositoryException(e);
    } catch (DfAuthenticationException e) {
      throw new RepositoryException(e);
    } catch (DfPrincipalException e) {
      throw new RepositoryException(e);
    } catch (DfServiceException e) {
      throw new RepositoryException(e);
    } catch (DfException e) {
      throw new RepositoryException(e);
    }
    return new DctmSession(dfSession);
  }

  public ISession newSession(String docbase) throws RepositoryException {
    IDfSession dfSession = null;
    try {
      dfSession = dfSessionManager.newSession(docbase);
    } catch (DfIdentityException e) {
      throw new RepositoryException(e);
    } catch (DfAuthenticationException e) {
      throw new RepositoryException(e);
    } catch (DfPrincipalException e) {
      throw new RepositoryException(e);
    } catch (DfServiceException e) {
      throw new RepositoryException(e);
    } catch (NoClassDefFoundError e) {
      throw new RepositoryException(e);
    }
    return new DctmSession(dfSession);
  }

  public void setIdentity(String docbase, ILoginInfo identity)
      throws RepositoryException {
    if (!(identity instanceof DctmLoginInfo)) {
      throw new IllegalArgumentException();
    }
    DctmLoginInfo dctmLoginInfo = (DctmLoginInfo) identity;
    logger.finer("Set identity: " + identity.getUser());
    IDfLoginInfo idfLoginInfo = dctmLoginInfo.getIdfLoginInfo();
    try {
      dfSessionManager.setIdentity(docbase, idfLoginInfo);
    } catch (DfServiceException e) {
      throw new RepositoryException(e);
    }
  }

  public void release(ISession session) {
    IDfSession dfSession = ((DctmSession) session).getDfSession();
    logger.finest("before session released: " + dfSession);
    dfSessionManager.release(dfSession);
    logger.finest("after session released");
  }
}
