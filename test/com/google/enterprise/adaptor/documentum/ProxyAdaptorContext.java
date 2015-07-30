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
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.DocIdEncoder;
import com.google.enterprise.adaptor.PollingIncrementalLister;
import com.google.enterprise.adaptor.SensitiveValueDecoder;

import java.net.URI;
import java.net.URISyntaxException;

class ProxyAdaptorContext {
  public static AdaptorContext getInstance() {
    return Proxies.newProxyInstance(AdaptorContext.class,
        new AdaptorContextMock());
  }

  private static class AdaptorContextMock {
    private final Config config = new Config();
    private final DocIdEncoder docIdEncoder = new MockDocIdCodec();
    private final SensitiveValueDecoder sensitiveValueDecoder = 
        new MockSensitiveValueDecoder();

    public Config getConfig() {
      return config;
    }

    public DocIdEncoder getDocIdEncoder() {
      return docIdEncoder;
    }

    public SensitiveValueDecoder getSensitiveValueDecoder() {
      return sensitiveValueDecoder;
    }

    public void setPollingIncrementalLister(
        PollingIncrementalLister pollingIncrementalLister) {
      // do nothing
    }
  }

  /**
   * Mock of {@link DocIdCodec}, derived from adaptor library implementation.
   */
  private static class MockDocIdCodec implements DocIdEncoder {
    private static final URI baseDocUri = URI.create("http://localhost/duck/");

    @Override
    public URI encodeDocId(DocId docId) {
      URI resource;
      String uniqueId = docId.getUniqueId();
      // Add three dots to any sequence of only dots. This is to allow "/../"
      // and "/./" within DocIds.
      uniqueId = uniqueId.replaceAll("(^|/)(\\.+)(?=$|/)", "$1$2...");
      // Also encode "//" except when after a ":".
      uniqueId = uniqueId.replaceAll("(?<!:)/(?=/)", "/...");
      // Precede index.html and index.htm with "_" to avoid GSA eating them.
      uniqueId = uniqueId.replaceFirst("(^|/)(_*index.html?)$", "$1_$2");
      // If starts with "/" avoid double slash after baseDocUri.
      if (uniqueId.startsWith("/")) { 
        uniqueId = "..." + uniqueId;
      }
      try {
        resource = new URI(null, null, baseDocUri.getPath() + uniqueId, null);
      } catch (URISyntaxException ex) {
        throw new IllegalStateException(ex);
      }
      return baseDocUri.resolve(resource);
    }
  }

  /**
   * Provides parsing of sensitive values that can be plain text, obfuscated, or
   * encrypted.
   */
  private static class MockSensitiveValueDecoder
      implements SensitiveValueDecoder {

    @Override
    public String decodeValue(String value) {
      return value.toUpperCase();
    }
  }
}
