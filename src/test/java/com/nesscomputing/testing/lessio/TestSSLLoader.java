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

import com.google.common.io.Resources;
import com.kaching.platform.common.Option;

import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.ResourceHandler;
import org.eclipse.jetty.server.ssl.SslSelectChannelConnector;
import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.net.URL;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.KeyAgreement;

public class TestSSLLoader extends LessIOSecurityManagerTestHelper
{
    private LessIOSecurityManager sm;

    @Before
    public void setupSecurityManager()
    {
        sm = new LessIOSecurityManager();
    }

    @Test
    public void testSSLServer()
        throws Exception
    {
        final Server server = new Server();

        assertAllowed(sm, new SSLServer(server), Option.<Class<? extends Exception>>none());

        Assert.assertTrue(server.isStarted());
        server.stop();
    }

    @Test
    public void testKeyAgreement()
        throws Exception
    {
        final AtomicReference<KeyAgreement> holder = new AtomicReference<>();

        assertAllowed(sm, new RunnableWithException() {

            @Override
            public void run() throws Exception
            {
                holder.set(KeyAgreement.getInstance("ECDH"));
            }
        }, Option.<Class<? extends Exception>>none());

        Assert.assertNotNull(holder.get());
    }


    @AllowNetworkListen(ports = {0})
    protected class SSLServer implements RunnableWithException
    {
        private final Server server;

        private SSLServer(final Server server)
        {
            this.server = server;
        }

        @Override
        public void run() throws Exception
        {
            final ResourceHandler resourceHandler = new ResourceHandler();
            resourceHandler.setBaseResource(Resource.newClassPathResource("/"));

            final URL keystoreUrl = Resources.getResource(TestSSLLoader.class, "/test-keystore.jks");

            final SslContextFactory contextFactory = new SslContextFactory();

            contextFactory.setKeyStorePath(keystoreUrl.toString());
            contextFactory.setKeyStorePassword("changeit");
            contextFactory.setKeyManagerPassword("changeit");

            final SslSelectChannelConnector scc = new SslSelectChannelConnector(contextFactory);
            scc.setPort(0);
            scc.setHost("localhost");

            server.setConnectors(new Connector[] { scc });
            server.setHandler(resourceHandler);

            server.start();

        }
    }
}
