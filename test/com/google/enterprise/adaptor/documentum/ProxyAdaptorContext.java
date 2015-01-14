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

import com.google.enterprise.adaptor.AdaptorContext;
import com.google.enterprise.adaptor.Config;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

public class ProxyAdaptorContext {
  public static AdaptorContext getInstance() {
    return (AdaptorContext) Proxy.newProxyInstance(
        AdaptorContext.class.getClassLoader(),
        new Class<?>[] {AdaptorContext.class}, new Handler());
  }

  private static class Handler implements InvocationHandler {
    private final Config config = new Config();

    public Object invoke(Object proxy, Method method, Object[] args) {
      if ("getConfig".equals(method.getName())) {
        return config;
      }
      throw new AssertionError("invalid method: " + method.getName());
    }
  }
}
