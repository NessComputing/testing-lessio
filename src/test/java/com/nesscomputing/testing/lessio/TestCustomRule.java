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

import java.net.Inet4Address;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

@AllowDNSResolution
public class TestCustomRule extends LessIOSecurityManagerTestHelper
{
    @Rule
    public DisallowedOperationRule testRule = new DisallowedOperationRule();

    public static class DisallowedOperationRule implements TestRule
    {
        private DisallowedOperationWrapper wrapper = null;
        @Override
        public Statement apply(Statement base, final Description description)
        {
            wrapper = new DisallowedOperationWrapper(base);
            return wrapper;
        }

        public boolean getSuccess()
        {
            return wrapper != null && wrapper.success;
        }

        public static class DisallowedOperationWrapper extends Statement
        {
            private boolean success = false;
            private final Statement delegate;

            DisallowedOperationWrapper(final Statement delegate)
            {
                this.delegate = delegate;
            }

            @Override
            public void evaluate() throws Throwable {
                Inet4Address.getByName("example.com");

                success = true;

                delegate.evaluate();
            }

        }
    }

    private LessIOSecurityManager sm;

    @Before
    public void setupSecurityManager()
    {
        sm = new LessIOSecurityManager();
    }

    @Test
    public void testSimple()
    {
        Assert.assertNotNull(sm);
        Assert.assertTrue(testRule.getSuccess());
    }
}


