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
import org.junit.runner.RunWith;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.InitializationError;

import com.nesscomputing.testing.lessio.TestCustomRunner.CustomRunner;

@RunWith(CustomRunner.class)
public class TestCustomRunner extends LessIOSecurityManagerTestHelper
{
    protected class DisallowedOperation implements RunnableWithException
    {
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

    public static class CustomRunner extends BlockJUnit4ClassRunner
    {
        public CustomRunner(Class<?> klass) throws InitializationError
        {
            super(klass);
        }
    }

}
