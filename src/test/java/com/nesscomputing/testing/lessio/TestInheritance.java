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

public class TestInheritance extends LessIOSecurityManagerTestHelper
{
    protected class DisallowedOperation implements RunnableWithException
    {
        public void run() throws IOException
        {
            Inet4Address.getByName("example.com");
        }
    }

    @AllowDNSResolution
    protected abstract class BaseOperation
    {
    }

    protected class AllowedOperation extends BaseOperation implements RunnableWithException
    {
        @Override
        public void run() throws IOException
        {
            Inet4Address.getByName("example.com");
        }
    }

    private LessIOSecurityManager sm;

    @Before
    public void setupSecurityManager()
    {
        sm = new LessIOSecurityManager();
    }

    @Test
    public void testNonAnnotatedOperation()
    {
        assertDisallowed(sm, new DisallowedOperation());
    }

    @Test
    public void testAnnotatedOperations()
    {
        assertAllowed(sm, new AllowedOperation(), Option.<Class<? extends Exception>> none());
    }
}
