/**
 * Copyright (C) 2011-2012 Ness Computing, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.nesscomputing.testing.lessio;

import java.io.IOException;
import java.net.Inet4Address;

import org.junit.Before;
import org.junit.Test;

import com.kaching.platform.common.Option;
import com.nesscomputing.testing.lessio.AllowDNSResolution;
import com.nesscomputing.testing.lessio.LessIOSecurityManager;

public class AllowDNSResolutionTest extends LessIOSecurityManagerTestHelper {
  protected class DisallowedOperation implements RunnableWithException {
    @Override
    public void run() throws IOException {
      Inet4Address.getByName("example.com");
    }
  }

  protected class LocalhostOperation implements RunnableWithException {
    @Override
    public void run() throws IOException {
        Inet4Address.getByName("127.0.0.1");
        Inet4Address.getByName("localhost");
        Inet4Address.getByName("::1");
      }
    }

  @AllowDNSResolution
  protected class AllowedOperation extends DisallowedOperation {
    @Override
    public void run() throws IOException {
      super.run();
    }
  }

  LessIOSecurityManager sm;

  @Before
  public void setupSecurityManager() {
    sm = new LessIOSecurityManager();
  }

  @Test
  public void testNonAnnotatedOperation() {
    assertDisallowed(sm, new DisallowedOperation());
  }

  @Test
  public void testNonAnnotatedLocalhost() {
    assertAllowed(sm, new LocalhostOperation(), Option.<Class<? extends Exception>> none());
  }

  @Test
  public void testAnnotatedOperations() {
    assertAllowed(sm, new AllowedOperation(),
        Option.<Class<? extends Exception>> none());
  }
}
