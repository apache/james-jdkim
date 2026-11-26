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

import org.apache.james.jdkim.api.BodyLengthPolicy;
import org.apache.james.jdkim.api.PublicKeyRecordRetriever;
import org.apache.james.jdkim.api.UnsignedDuplicateFieldPolicy;
import org.apache.james.jdkim.api.VerifierOptions;
import org.apache.james.jdkim.impl.DNSPublicKeyRecordRetriever;
import org.apache.james.jdkim.impl.MultiplexingPublicKeyRecordRetriever;
import org.junit.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TXTRecord;

import java.io.ByteArrayInputStream;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
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

    @Test
    public void shouldReturnDefaultMaxSignatures() {
        VerifierOptions opt = new VerifierOptions.Builder().build();
        assertEquals(32, opt.getMaxSignatures());
    }

    @Test
    public void shouldReadMaxSignaturesFromSystemProperty() {
        System.setProperty(VerifierOptions.MAX_SIGNATURE_COUNT_PROPERTY, "7");
        try {
            VerifierOptions opt = new VerifierOptions.Builder().build();
            assertEquals(7, opt.getMaxSignatures());
        } finally {
            System.clearProperty(VerifierOptions.MAX_SIGNATURE_COUNT_PROPERTY);
        }
    }

    @Test
    public void shouldReturnCorrectMaxSignatures() {
        VerifierOptions opt = new VerifierOptions.Builder().withMaxSignatures(5).build();
        assertEquals(5, opt.getMaxSignatures());
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRejectNonPositiveMaxSignatures() {
        new VerifierOptions.Builder().withMaxSignatures(0).build();
    }

    @Test
    public void shouldRejectUnsignedDuplicateFieldsByDefault() {
        VerifierOptions opt = new VerifierOptions.Builder().build();
        assertEquals(UnsignedDuplicateFieldPolicy.REJECT, opt.getUnsignedDuplicateFieldPolicy());
        assertEquals(Collections.singleton("from"), opt.getSingleInstanceFields());
    }

    @Test
    public void shouldReadUnsignedDuplicateFieldPolicyFromSystemProperty() {
        System.setProperty(VerifierOptions.UNSIGNED_DUPLICATE_FIELD_POLICY_PROPERTY, "flag");
        try {
            VerifierOptions opt = new VerifierOptions.Builder().build();
            assertEquals(UnsignedDuplicateFieldPolicy.FLAG, opt.getUnsignedDuplicateFieldPolicy());
        } finally {
            System.clearProperty(VerifierOptions.UNSIGNED_DUPLICATE_FIELD_POLICY_PROPERTY);
        }
    }

    @Test
    public void shouldReturnCorrectUnsignedDuplicateFieldPolicy() {
        VerifierOptions opt = new VerifierOptions.Builder().withUnsignedDuplicateFieldPolicy(UnsignedDuplicateFieldPolicy.ACCEPT).build();
        assertEquals(UnsignedDuplicateFieldPolicy.ACCEPT, opt.getUnsignedDuplicateFieldPolicy());
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRejectNullUnsignedDuplicateFieldPolicy() {
        new VerifierOptions.Builder().withUnsignedDuplicateFieldPolicy(null).build();
    }

    @Test
    public void shouldFlagUnsignedBodyOctetsByDefault() {
        assertEquals(BodyLengthPolicy.FLAG, new VerifierOptions.Builder().build().getBodyLengthPolicy());
    }

    @Test
    public void shouldReadBodyLengthPolicyFromSystemProperty() {
        System.setProperty(VerifierOptions.BODY_LENGTH_POLICY_PROPERTY, "reject");
        try {
            assertEquals(BodyLengthPolicy.REJECT, new VerifierOptions.Builder().build().getBodyLengthPolicy());
        } finally {
            System.clearProperty(VerifierOptions.BODY_LENGTH_POLICY_PROPERTY);
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRejectNullBodyLengthPolicy() {
        new VerifierOptions.Builder().withBodyLengthPolicy(null).build();
    }

    @Test
    public void shouldLowerCaseSingleInstanceFields() {
        VerifierOptions opt = new VerifierOptions.Builder().withSingleInstanceFields(Arrays.asList("From", " SUBJECT ")).build();
        assertEquals(new LinkedHashSet<>(Arrays.asList("from", "subject")), opt.getSingleInstanceFields());
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRejectNullSingleInstanceFields() {
        new VerifierOptions.Builder().withSingleInstanceFields(null).build();
    }

    @Test
    public void shouldRequire1024BitRsaKeysByDefault() {
        assertEquals(1024, new VerifierOptions.Builder().build().getMinimumRsaKeyBits());
    }

    @Test
    public void shouldReadMinimumRsaKeyBitsFromSystemProperty() {
        System.setProperty(VerifierOptions.MIN_RSA_KEY_BITS_PROPERTY, "2048");
        try {
            assertEquals(2048, new VerifierOptions.Builder().build().getMinimumRsaKeyBits());
        } finally {
            System.clearProperty(VerifierOptions.MIN_RSA_KEY_BITS_PROPERTY);
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRejectNegativeMinimumRsaKeyBits() {
        new VerifierOptions.Builder().withMinimumRsaKeyBits(-1).build();
    }

    @Test
    public void shouldAccept8192BitRsaKeysAtMostByDefault() {
        assertEquals(8192, new VerifierOptions.Builder().build().getMaximumRsaKeyBits());
    }

    @Test
    public void shouldReadMaximumRsaKeyBitsFromSystemProperty() {
        System.setProperty(VerifierOptions.MAX_RSA_KEY_BITS_PROPERTY, "4096");
        try {
            assertEquals(4096, new VerifierOptions.Builder().build().getMaximumRsaKeyBits());
        } finally {
            System.clearProperty(VerifierOptions.MAX_RSA_KEY_BITS_PROPERTY);
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRejectMaximumRsaKeyBitsBelowMinimum() {
        new VerifierOptions.Builder().withMinimumRsaKeyBits(2048).withMaximumRsaKeyBits(1024).build();
    }

    @Test
    public void shouldAllowRsaSha1ByDefault() {
        assertTrue(new VerifierOptions.Builder().build().isRsaSha1Allowed());
    }

    @Test
    public void shouldReadRsaSha1AllowedFromSystemProperty() {
        System.setProperty(VerifierOptions.RSA_SHA1_ALLOWED_PROPERTY, "false");
        try {
            assertFalse(new VerifierOptions.Builder().build().isRsaSha1Allowed());
        } finally {
            System.clearProperty(VerifierOptions.RSA_SHA1_ALLOWED_PROPERTY);
        }
    }

    /**
     * Answers every query with the given TXT record, and remembers the queried names.
     */
    private static Resolver stubResolver(List<Name> queried, String txt) throws UnknownHostException {
        return new SimpleResolver("127.0.0.1") {
            @Override
            public Message send(Message query) {
                Name name = query.getQuestion().getName();
                queried.add(name);
                Message response = new Message(query.getHeader().getID());
                response.getHeader().setFlag(Flags.QR);
                response.addRecord(query.getQuestion(), Section.QUESTION);
                // a character-string holds at most 255 octets
                List<String> strings = new ArrayList<>();
                for (int i = 0; i < txt.length(); i += 255) {
                    strings.add(txt.substring(i, Math.min(txt.length(), i + 255)));
                }
                response.addRecord(new TXTRecord(name, DClass.IN, 3600, strings), Section.ANSWER);
                return response;
            }
        };
    }

    @Test
    public void defaultRetrieverShouldUseTheConfiguredDnsResolver() throws Exception {
        Lookup.getDefaultCache(DClass.IN).clearCache();
        List<Name> queried = new CopyOnWriteArrayList<>();
        String key = "k=rsa; p=" + Base64.getEncoder().encodeToString(TestKeys.publicKey.getEncoded()) + ";";
        VerifierOptions opt = new VerifierOptions.Builder()
                .withDnsResolver(stubResolver(queried, key))
                .build();
        byte[] mail = "From: joe@messiah.edu\r\n\r\nbody\r\n".getBytes(StandardCharsets.US_ASCII);
        String field = new DKIMSigner("v=1; a=rsa-sha256; c=simple; d=resolver-option.invalid; h=from; s=stub;",
                TestKeys.privateKey).sign(new ByteArrayInputStream(mail));
        byte[] signed = (field + "\r\n" + new String(mail, StandardCharsets.US_ASCII)).getBytes(StandardCharsets.US_ASCII);

        assertThat(new DKIMVerifier(opt).verify(new ByteArrayInputStream(signed))).hasSize(1);
        assertThat(queried).containsExactly(Name.fromString("stub._domainkey.resolver-option.invalid."));
    }

    @Test
    public void explicitRetrieverShouldWinOverTheDnsResolver() throws Exception {
        List<Name> queried = new CopyOnWriteArrayList<>();
        Resolver resolver = stubResolver(queried, "v=DKIM1; p=AAAA");
        PublicKeyRecordRetriever retriever = new MockPublicKeyRecordRetriever();

        VerifierOptions resolverFirst = new VerifierOptions.Builder()
                .withDnsResolver(resolver)
                .withPublicKeyRecordRetriever(retriever)
                .build();
        VerifierOptions retrieverFirst = new VerifierOptions.Builder()
                .withPublicKeyRecordRetriever(retriever)
                .withDnsResolver(resolver)
                .build();

        assertThat(resolverFirst.getPublicKeyRecordRetriever()).isSameAs(retriever);
        assertThat(retrieverFirst.getPublicKeyRecordRetriever()).isSameAs(retriever);
        assertThat(queried).isEmpty();
    }

    @Test
    public void shouldRejectNullPublicKeyRecordRetriever() {
        assertThatThrownBy(() -> new VerifierOptions.Builder().withPublicKeyRecordRetriever(null).build())
                .isInstanceOf(IllegalArgumentException.class);
    }
}
