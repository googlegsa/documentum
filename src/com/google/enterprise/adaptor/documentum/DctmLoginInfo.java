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

import com.documentum.fc.common.IDfLoginInfo;
import com.google.enterprise.adaptor.InvalidConfigurationException;

public class DctmLoginInfo implements ILoginInfo {
  private final IDfLoginInfo idfLoginInfo;

  public DctmLoginInfo(IDfLoginInfo idfLoginInfo) {
    if (idfLoginInfo == null) {
      throw new InvalidConfigurationException("Argument can't be null");
    } else {
      this.idfLoginInfo = idfLoginInfo;
    }
  }

  public void setUser(String user) {
    idfLoginInfo.setUser(user);
  }

  public void setPassword(String password) {
    idfLoginInfo.setPassword(password);
  }

  public String getUser() {
    return idfLoginInfo.getUser();
  }

  public String getPassword() {
    return idfLoginInfo.getPassword();
  }

  public IDfLoginInfo getIdfLoginInfo() {
    return idfLoginInfo;
  }
}
