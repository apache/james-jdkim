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

import static org.assertj.core.api.Assertions.assertThat;
import java.util.List;
import java.util.Arrays;
import org.xbill.DNS.Name;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.DClass;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.Flags;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Message;
import org.apache.james.jdkim.api.PublicKeyRecord;
import org.apache.james.jdkim.api.PublicKeyRecordRetriever;
import org.apache.james.jdkim.api.VerifierOptions;
import org.apache.james.jdkim.exceptions.FailException;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.exceptions.TempFailException;
import org.apache.james.jdkim.impl.DNSPublicKeyRecordRetriever;
import org.apache.james.jdkim.tagvalue.TagValue;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAKey;
import java.security.spec.InvalidKeySpecException;

public class DNSPublicKeyRetrieverTest {

    @Test
    public void testWrongOption() throws TempFailException {
        try {
            new DNSPublicKeyRecordRetriever().getRecords("somethingelse",
                    "test", "test");
            Assert.fail("expected unsupported operation");
        } catch (PermFailException e) {
        }
    }

    @Test
    public void testConstructor() {
        new DNSPublicKeyRecordRetriever();
    }

    /**
     * TODO: Requires internet connection
     *
     * @throws PermFailException
     */
    @Test
    public void testRetrieve() throws TempFailException, PermFailException {
        PublicKeyRecordRetriever pkr = new DNSPublicKeyRecordRetriever();
        pkr.getRecords("dns/txt", "lima", "yahoogroups.com");
        pkr.getRecords("dns/txt", "20230601", "gmail.com");

        new TagValue(pkr.getRecords("dns/txt", "lima", "yahoogroups.com").get(0));
    }

    @Test
    public void testKeyPair() throws PermFailException, TempFailException,
            NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKeyRecord key = new DKIMVerifier()
                .publicKeySelector(new MockPublicKeyRecordRetriever(
                        "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDYDaYKXzwVYwqWbLhmuJ66aTAN8wmDR+rfHE8HfnkSOax0oIoTM5zquZrTLo30870YMfYzxwfB6j/Nz3QdwrUD/t0YMYJiUKyWJnCKfZXHJBJ+yfRHr7oW+UW3cVo9CG2bBfIxsInwYe175g9UjyntJpWueqdEIo1c2bhv9Mp66QIDAQAB;",
                        "dummy", "dummy").getRecords("dns/txt", "dummy",
                        "dummy"));

        // String privateKey =
        // "MIICXAIBAAKBgQDYDaYKXzwVYwqWbLhmuJ66aTAN8wmDR+rfHE8HfnkSOax0oIoTM5zquZrTLo30870YMfYzxwfB6j/Nz3QdwrUD/t0YMYJiUKyWJnCKfZXHJBJ+yfRHr7oW+UW3cVo9CG2bBfIxsInwYe175g9UjyntJpWueqdEIo1c2bhv9Mp66QIDAQABAoGBAI8XcwnZi0Sq5N89wF+gFNhnREFo3rsJDaCY8iqHdA5DDlnr3abb/yhipw0I/1HlgC6fIG2oexXOXFWl+USgqRt1kTt9jXhVFExg8mNko2UelAwFtsl8CRjVcYQOcedeH/WM/mXjg2wUqqZenBmlKlD6vNb70jFJeVaDJ/7n7j8BAkEA9NkH2D4Zgj/IOAVYccZYH74+VgO0e7VkUjQk9wtJ2j6cGqJ6Pfj0roVIMUWzoBb8YfErR8l6JnVQbfy83gJeiQJBAOHk3ow7JjAn8XuOyZx24KcTaYWKUkAQfRWYDFFOYQF4KV9xLSEtycY0kjsdxGKDudWcsATllFzXDCQF6DTNIWECQEA52ePwTjKrVnLTfCLEG4OgHKvlZud4amthwDyJWoMEH2ChNB2je1N4JLrABOE+hk+OuoKnKAKEjWd8f3Jg/rkCQHj8mQmogHqYWikgP/FSZl518jV48Tao3iXbqvU9Mo2T6yzYNCCqIoDLFWseNVnCTZ0Qb+IfiEf1UeZVV5o4J+ECQDatNnS3V9qYUKjj/krNRD/U0+7eh8S2ylLqD3RlSn9KtYGRMgAtUXtiOEizBH6bd/orzI9V9sw8yBz+ZqIH25Q=";
        String privateKeyPKCS8 = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBANgNpgpfPBVjCpZsuGa4nrppMA3zCYNH6t8cTwd+eRI5rHSgihMznOq5mtMujfTzvRgx9jPHB8HqP83PdB3CtQP+3RgxgmJQrJYmcIp9lcckEn7J9Eevuhb5RbdxWj0IbZsF8jGwifBh7XvmD1SPKe0mla56p0QijVzZuG/0ynrpAgMBAAECgYEAjxdzCdmLRKrk3z3AX6AU2GdEQWjeuwkNoJjyKod0DkMOWevdptv/KGKnDQj/UeWALp8gbah7Fc5cVaX5RKCpG3WRO32NeFUUTGDyY2SjZR6UDAW2yXwJGNVxhA5x514f9Yz+ZeODbBSqpl6cGaUqUPq81vvSMUl5VoMn/ufuPwECQQD02QfYPhmCP8g4BVhxxlgfvj5WA7R7tWRSNCT3C0naPpwaono9+PSuhUgxRbOgFvxh8StHyXomdVBt/LzeAl6JAkEA4eTejDsmMCfxe47JnHbgpxNphYpSQBB9FZgMUU5hAXgpX3EtIS3JxjSSOx3EYoO51ZywBOWUXNcMJAXoNM0hYQJAQDnZ4/BOMqtWctN8IsQbg6Acq+Vm53hqa2HAPIlagwQfYKE0HaN7U3gkusAE4T6GT466gqcoAoSNZ3x/cmD+uQJAePyZCaiAephaKSA/8VJmXnXyNXjxNqjeJduq9T0yjZPrLNg0IKoigMsVax41WcJNnRBv4h+IR/VR5lVXmjgn4QJANq02dLdX2phQqOP+Ss1EP9TT7t6HxLbKUuoPdGVKf0q1gZEyAC1Re2I4SLMEfpt3+ivMj1X2zDzIHP5mogfblA==";

        PrivateKey privKey = DKIMSigner.getPrivateKey(privateKeyPKCS8);

        // controllo che il modulus della chiave privata corrisponda al record
        // pubblico
        Assert.assertEquals(((RSAKey) privKey).getModulus(), ((RSAKey) key
                .getPublicKey()).getModulus());
    }

    @Test
    public void testSignVerify() throws NoSuchAlgorithmException,
            InvalidKeySpecException, IOException, FailException {
        MockPublicKeyRecordRetriever mockPublicKeyRecordRetriever = new MockPublicKeyRecordRetriever(
                "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDYDaYKXzwVYwqWbLhmuJ66aTAN8wmDR+rfHE8HfnkSOax0oIoTM5zquZrTLo30870YMfYzxwfB6j/Nz3QdwrUD/t0YMYJiUKyWJnCKfZXHJBJ+yfRHr7oW+UW3cVo9CG2bBfIxsInwYe175g9UjyntJpWueqdEIo1c2bhv9Mp66QIDAQAB;",
                "selector", "example.com");
        PublicKeyRecord key = new DKIMVerifier()
                .publicKeySelector(mockPublicKeyRecordRetriever.getRecords(
                        "dns/txt", "selector", "example.com"));
        String privateKeyPKCS8 = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBANgNpgpfPBVjCpZsuGa4nrppMA3zCYNH6t8cTwd+eRI5rHSgihMznOq5mtMujfTzvRgx9jPHB8HqP83PdB3CtQP+3RgxgmJQrJYmcIp9lcckEn7J9Eevuhb5RbdxWj0IbZsF8jGwifBh7XvmD1SPKe0mla56p0QijVzZuG/0ynrpAgMBAAECgYEAjxdzCdmLRKrk3z3AX6AU2GdEQWjeuwkNoJjyKod0DkMOWevdptv/KGKnDQj/UeWALp8gbah7Fc5cVaX5RKCpG3WRO32NeFUUTGDyY2SjZR6UDAW2yXwJGNVxhA5x514f9Yz+ZeODbBSqpl6cGaUqUPq81vvSMUl5VoMn/ufuPwECQQD02QfYPhmCP8g4BVhxxlgfvj5WA7R7tWRSNCT3C0naPpwaono9+PSuhUgxRbOgFvxh8StHyXomdVBt/LzeAl6JAkEA4eTejDsmMCfxe47JnHbgpxNphYpSQBB9FZgMUU5hAXgpX3EtIS3JxjSSOx3EYoO51ZywBOWUXNcMJAXoNM0hYQJAQDnZ4/BOMqtWctN8IsQbg6Acq+Vm53hqa2HAPIlagwQfYKE0HaN7U3gkusAE4T6GT466gqcoAoSNZ3x/cmD+uQJAePyZCaiAephaKSA/8VJmXnXyNXjxNqjeJduq9T0yjZPrLNg0IKoigMsVax41WcJNnRBv4h+IR/VR5lVXmjgn4QJANq02dLdX2phQqOP+Ss1EP9TT7t6HxLbKUuoPdGVKf0q1gZEyAC1Re2I4SLMEfpt3+ivMj1X2zDzIHP5mogfblA==";
        PrivateKey privKey = DKIMSigner.getPrivateKey(privateKeyPKCS8);

        // Check that the private key modulus equals the public key modulus
        Assert.assertEquals(((RSAKey) privKey).getModulus(), ((RSAKey) key
                .getPublicKey()).getModulus());

        DKIMSigner signer = new DKIMSigner(
                "v=1; s=selector; d=example.com; h=from:to; a=rsa-sha256; bh=; b=;",
                privKey);
        String message = "From: test@example.com\r\nTo: test@example.com\r\n\r\nbody\r\n";
        String res = signer.sign(new ByteArrayInputStream(message.getBytes()));
        String signedMessage = res + "\r\n"
                + "From: test@example.com\r\nTo: test@example.com\r\n\r\nbody\r\n";

        new DKIMVerifier(new VerifierOptions.Builder().withPublicKeyRecordRetriever(mockPublicKeyRecordRetriever).build())
                .verify(new ByteArrayInputStream(signedMessage.getBytes()));

    }

    @Test
    public void runtimeExceptionFromTheResolverShouldBeATempFail() throws Exception {
        Resolver resolver = new SimpleResolver("127.0.0.1") {
            @Override
            public Message send(Message query) {
                throw new IndexOutOfBoundsException("malformed answer");
            }
        };

        assertThatThrownBy(() -> new DNSPublicKeyRecordRetriever(resolver).getRecords("dns/txt", "sel", "example.com"))
                .isInstanceOf(TempFailException.class);
    }

    @Test
    public void txtStringsShouldBeReturnedRaw() throws Exception {
        TXTRecord[] answer = new TXTRecord[1];
        Resolver resolver = new SimpleResolver("127.0.0.1") {
            @Override
            public Message send(Message query) {
                Message response = new Message(query.getHeader().getID());
                response.getHeader().setFlag(Flags.QR);
                response.addRecord(query.getQuestion(), Section.QUESTION);
                answer[0] = new TXTRecord(query.getQuestion().getName(), DClass.IN, 3600,
                        Arrays.asList("v=DKIM1; n=\\\"quoted\\\" \\\\ note \\147;", " p=AAAA"));
                response.addRecord(answer[0], Section.ANSWER);
                return response;
            }
        };

        Lookup.getDefaultCache(DClass.IN).clearCache();

        assertThat(new DNSPublicKeyRecordRetriever(resolver).getRecords("dns/txt", "raw", "example.com"))
                .containsExactly("v=DKIM1; n=\"quoted\" \\ note \u0093; p=AAAA");
    }

    @Test
    public void keyRecordsShouldOnlyBeLookedUpAtTheAbsoluteName() throws Exception {
        Resolver resolver = new SimpleResolver("127.0.0.1") {
            @Override
            public Message send(Message query) {
                Message response = new Message(query.getHeader().getID());
                response.getHeader().setFlag(Flags.QR);
                response.addRecord(query.getQuestion(), Section.QUESTION);
                Name name = query.getQuestion().getName();
                if (name.toString().equals("search._domainkey.example.com.search.invalid.")) {
                    response.addRecord(new TXTRecord(name, DClass.IN, 3600, "v=DKIM1; p=AAAA"), Section.ANSWER);
                } else {
                    response.getHeader().setRcode(Rcode.NXDOMAIN);
                }
                return response;
            }
        };
        Lookup.getDefaultCache(DClass.IN).clearCache();
        List<Name> savedSearchPath = Lookup.getDefaultSearchPath();
        Lookup.setDefaultSearchPath(Name.fromString("search.invalid."));
        try {
            assertThat(new DNSPublicKeyRecordRetriever(resolver).getRecords("dns/txt", "search", "example.com")).isEmpty();
        } finally {
            Lookup.setDefaultSearchPath(savedSearchPath);
        }
    }
}
