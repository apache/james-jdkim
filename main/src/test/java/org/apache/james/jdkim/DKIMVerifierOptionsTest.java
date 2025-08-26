/****************************************************************
 * Licensed to the Apache Software Foundation (ASF) under one   *
 * or more contributor license agreements.  See the NOTICE file *
 * distributed with this work for additional information        *
 * regarding copyright ownership.  The ASF licenses this file   *
 * to you under the Apache License, Version 2.0 (the            *
 * "License"); you may not use this file except in compliance   *
 * with the License.  You may obtain a copy of the License at   *
 *                                                              *
 *   http://www.apache.org/licenses/LICENSE-2.0                 *
 *                                                              *
 * Unless required by applicable law or agreed to in writing,   *
 * software distributed under the License is distributed on an  *
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY       *
 * KIND, either express or implied.  See the License for the    *
 * specific language governing permissions and limitations      *
 * under the License.                                           *
 ****************************************************************/

package org.apache.james.jdkim;

import org.apache.james.jdkim.api.PublicKeyRecordRetriever;
import org.apache.james.jdkim.api.VerifierOptions;
import org.apache.james.jdkim.impl.DNSPublicKeyRecordRetriever;
import org.apache.james.jdkim.impl.MultiplexingPublicKeyRecordRetriever;
import org.junit.Test;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SimpleResolver;

import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.time.Duration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class DKIMVerifierOptionsTest {

    @Test
    public void shouldNotReturnNullClockDriftTolerance() {
        VerifierOptions opt = new VerifierOptions.Builder().build();
        assertNotNull(opt);
        assertNotNull(opt.getClockDriftTolerance());
    }

    @Test
    public void shouldReturnCorrectClockDriftTolerance() {
        Duration duration = Duration.ofSeconds(1234);
        VerifierOptions opt = new VerifierOptions.Builder().withClockDriftTolerance(duration).build();
        assertEquals(duration.toMillis(), opt.getClockDriftTolerance().toMillis());
    }

    @Test
    public void shouldReturnDefaultClockDriftTolerance() {
        VerifierOptions opt = new VerifierOptions.Builder().build();
        assertEquals("Invalid clock drift", 300000L, opt.getClockDriftTolerance().toMillis());
    }

    @Test
    public void shouldNotReturnNullResolver() {
        VerifierOptions opt = new VerifierOptions.Builder().build();
        assertNotNull(opt);
        assertNotNull(opt.getDnsResolver());
    }

    @Test
    public void shouldReturnDnsResolver() throws UnknownHostException {
        Resolver resolver = new SimpleResolver("9.8.7.6");
        VerifierOptions opt = new VerifierOptions.Builder().withDnsResolver(resolver).build();
        assertEquals("Invalid dnsResolver", resolver, opt.getDnsResolver());
        assertTrue("Must be an instance of SimpleResolver", opt.getDnsResolver() instanceof SimpleResolver);
        assertEquals("Invalid hostname", new InetSocketAddress("9.8.7.6", 53), ((SimpleResolver) opt.getDnsResolver()).getAddress());
    }

    @Test
    public void shouldReturnDefaultResolver() throws UnknownHostException {
        Resolver defaultResolver = Lookup.getDefaultResolver();
        VerifierOptions opt = new VerifierOptions.Builder().build();
        assertEquals("Resolver is not the default", defaultResolver, opt.getDnsResolver());
    }

    @Test
    public void shouldNotReturnNullPublicKeyRecordRetriever() {
        VerifierOptions opt = new VerifierOptions.Builder().build();
        assertNotNull(opt);
        assertNotNull(opt.getPublicKeyRecordRetriever());
    }

    @Test
    public void shouldReturnDefaultPublicKeyRecordRetriever() {
        VerifierOptions opt = new VerifierOptions.Builder().build();
        assertTrue("Must be an instance of MultiplexingPublicKeyRecordRetriever", opt.getPublicKeyRecordRetriever() instanceof MultiplexingPublicKeyRecordRetriever);

    }

    @Test
    public void shouldReturnCorrectPublicKeyRecordRetriever() {
        PublicKeyRecordRetriever retr = new DNSPublicKeyRecordRetriever();
        VerifierOptions opt = new VerifierOptions.Builder().withPublicKeyRecordRetriever(retr).build();
        assertEquals("Invalid instance", retr, opt.getPublicKeyRecordRetriever());
        assertTrue("Must be an instance of DNSPublicKeyRecordRetriever", opt.getPublicKeyRecordRetriever() instanceof DNSPublicKeyRecordRetriever);
    }
}
