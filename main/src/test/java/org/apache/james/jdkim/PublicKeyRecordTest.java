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

import java.security.KeyPairGenerator;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.util.Base64;
import org.apache.james.jdkim.api.PublicKeyRecord;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.tagvalue.PublicKeyRecordImpl;
import org.apache.james.jdkim.tagvalue.SignatureRecordImpl;
import org.apache.james.jdkim.tagvalue.TagValue;
import org.junit.Assert;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.Test;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

public class PublicKeyRecordTest {

    @Test
    public void testValidate() {
        PublicKeyRecord pkr = new PublicKeyRecordImpl("");
        try {
            pkr.validate();
            fail("Expected failure: missing mandatory parameters");
        } catch (IllegalStateException e) {
        }
        pkr = new PublicKeyRecordImpl("k=rsa; p=XXXXXXXX=;");
        pkr.validate();
        pkr = new PublicKeyRecordImpl("v=DKIM1; k=rsa; p=XXXXXX=");
        pkr.validate();
        pkr = new PublicKeyRecordImpl(" v=DKIM1; k=rsa; p=XXXXXX=");
        pkr.validate();
        pkr = new PublicKeyRecordImpl("k=rsa; v=DKIM1; p=XXXXXX=");
        try {
            pkr.validate();
            fail("Expected failure: v should be the first");
        } catch (IllegalStateException e) {
        }
        pkr = new PublicKeyRecordImpl("v=DKIM2; k=rsa; p=XXXXXX=");
        try {
            pkr.validate();
            fail("Expected failure: wrong version");
        } catch (IllegalStateException e) {
        }
        pkr = new PublicKeyRecordImpl("v=DKIM1; k=rsa; p=");
        try {
            pkr.validate();
            fail("Expected failure: revoked key");
        } catch (IllegalStateException e) {
        }
    }

    @Test
    public void testIsHashMethodSupported() {
        PublicKeyRecord pkr = new PublicKeyRecordImpl("k=rsa; p=XXXXXXXX=;");
        pkr.validate();
        assertTrue(pkr.isHashMethodSupported("sha1"));
        assertTrue(pkr.isHashMethodSupported("sha256"));
        pkr = new PublicKeyRecordImpl("k=rsa; h=sha1:sha256; p=XXXXXXXX=;");
        pkr.validate();
        assertTrue(pkr.isHashMethodSupported("sha1"));
        assertFalse(pkr.isHashMethodSupported("sha128"));
        assertTrue(pkr.isHashMethodSupported("sha256"));
    }

    @Test
    public void testIsKeyTypeSupported() {
        PublicKeyRecord pkr = new PublicKeyRecordImpl("k=rsa; p=XXXXXXXX=;");
        pkr.validate();
        assertTrue(pkr.isKeyTypeSupported("rsa"));
        assertFalse(pkr.isKeyTypeSupported("dsa"));
    }

    @Test
    public void testGetAcceptableHashMethods() {
        PublicKeyRecord pkr = new PublicKeyRecordImpl(
                "k=rsa; h=sha1:sha256; p=XXXXXXXX=;");
        pkr.validate();
        List<CharSequence> methods = pkr.getAcceptableHashMethods();
        assertEquals("[sha1, sha256]", methods.toString());
        pkr = new PublicKeyRecordImpl("k=rsa; p=XXXXXXXX=;");
        pkr.validate();
        methods = pkr.getAcceptableHashMethods();
        Assert.assertNull(methods);
    }

    @Test
    public void testGetAcceptableKeyTypes() {
        PublicKeyRecord pkr = new PublicKeyRecordImpl(
                "k=rsa; h=sha1:sha256; p=XXXXXXXX=;");
        pkr.validate();
        List<CharSequence> methods = pkr.getAcceptableKeyTypes();
        assertEquals("[rsa]", methods.toString());
        pkr = new PublicKeyRecordImpl("k=rsa:dsa; p=XXXXXXXX=;");
        pkr.validate();
        methods = pkr.getAcceptableKeyTypes();
        assertEquals("[rsa, dsa]", methods.toString());
    }

    @Test
    public void testGetGranularityPattern() {
        PublicKeyRecord pkr = new PublicKeyRecordImpl(
                "k=rsa; h=sha1:sha256; p=XXXXXXXX=;");
        pkr.validate();
        Pattern pattern = pkr.getGranularityPattern();
        assertEquals("^\\Q\\E.*\\Q\\E$", pattern.pattern());
        assertTrue(pattern.matcher("something").matches());
        assertTrue(pattern.matcher("").matches());
        pkr = new PublicKeyRecordImpl("k=rsa; g=; h=sha1:sha256; p=XXXXXXXX=;");
        pkr.validate();
        pattern = pkr.getGranularityPattern();
        assertEquals("@", pattern.pattern());
        assertFalse(pattern.matcher("something").matches());
        assertFalse(pattern.matcher("").matches());
        pkr = new PublicKeyRecordImpl(
                "k=rsa; g=some*; h=sha1:sha256; p=XXXXXXXX=;");
        pkr.validate();
        pattern = pkr.getGranularityPattern();
        assertTrue(pattern.matcher("something").matches());
        assertTrue(pattern.matcher("some").matches());
        assertFalse(pattern.matcher("som").matches());
        assertFalse(pattern.matcher("awesome").matches());
        assertEquals("^\\Qsome\\E.*\\Q\\E$", pattern.pattern());
        pkr = new PublicKeyRecordImpl(
                "k=rsa; g=*+test; h=sha1:sha256; p=XXXXXXXX=;");
        pkr.validate();
        pattern = pkr.getGranularityPattern();
        assertEquals("^\\Q\\E.*\\Q+test\\E$", pattern.pattern());
        assertTrue(pattern.matcher("a+test").matches());
        assertTrue(pattern.matcher("+test").matches());
        assertFalse(pattern.matcher("atest").matches());
        assertFalse(pattern.matcher("+tested").matches());
        pkr = new PublicKeyRecordImpl(
                "k=rsa; g=test; h=sha1:sha256; p=XXXXXXXX=;");
        pkr.validate();
        pattern = pkr.getGranularityPattern();
        assertEquals("^\\Qtest\\E$", pattern.pattern());
        assertTrue(pattern.matcher("test").matches());
        assertFalse(pattern.matcher("atest").matches());
        assertFalse(pattern.matcher("testa").matches());
        try {
            pkr = new PublicKeyRecordImpl(
                    "k=rsa; g=*\\+test; h=sha1:sha256; p=XXXXXXXX=;");
            pkr.validate();
            pattern = pkr.getGranularityPattern();
            fail("Expected syntax error");
        } catch (IllegalStateException e) {
        }
        try {
            pkr = new PublicKeyRecordImpl(
                    "k=rsa; g=*test*; h=sha1:sha256; p=XXXXXXXX=;");
            pkr.validate();
            pattern = pkr.getGranularityPattern();
            fail("Expected syntax error");
        } catch (IllegalStateException e) {
        }
    }

    @Test
    public void testGetPublicKey() {
        PublicKeyRecord pkr = new PublicKeyRecordImpl(
                "k=rsa; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIhyR3oItOy22ZOaBrIVe9m/iME3RqOJeasANSpg2YTHTYV+Xtp4xwf5gTjCmHQEMOs0qYu0FYiNQPQogJ2t0Mfx9zNu06rfRBDjiIU9tpx2T+NGlWZ8qhbiLo5By8apJavLyqTLavyPSrvsx0B3YzC63T4Age2CDqZYA+OwSMWQIDAQAB");
        pkr.validate();
        PublicKey pk = pkr.getPublicKey();
        assertEquals("RSA", pk.getAlgorithm());
        // On older jvm this is X509
        // assertEquals("X.509", pk.getFormat());
        assertEquals(
                new BigInteger(
                        "140815480285950232210124449496973988135931539914762288985377502488754711434253259186192434865594456027796377309280714060984552676169392598862819043219650259702261370701494928576447797673342985377518637829874968725582762257956980427968667812066816497848410406856165942400151628259779523949079651036806330485849"),
                ((RSAKey) pk).getModulus());

        try {
            pkr = new PublicKeyRecordImpl(
                    "k=dsa; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIhyR3oItOy22ZOaBrIVe9m/iME3RqOJeasANSpg2YTHTYV+Xtp4xwf5gTjCmHQEMOs0qYu0FYiNQPQogJ2t0Mfx9zNu06rfRBDjiIU9tpx2T+NGlWZ8qhbiLo5By8apJavLyqTLavyPSrvsx0B3YzC63T4Age2CDqZYA+OwSMWQIDAQAB");
            pkr.validate();
            pk = pkr.getPublicKey();
            fail("Expected invalid key spec. DSA is not supported");
        } catch (IllegalStateException e) {
        }

        try {
            pkr = new PublicKeyRecordImpl(
                    "k=unknown; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIhyR3oItOy22ZOaBrIVe9m/iME3RqOJeasANSpg2YTHTYV+Xtp4xwf5gTjCmHQEMOs0qYu0FYiNQPQogJ2t0Mfx9zNu06rfRBDjiIU9tpx2T+NGlWZ8qhbiLo5By8apJavLyqTLavyPSrvsx0B3YzC63T4Age2CDqZYA+OwSMWQIDAQAB");
            pkr.validate();
            pk = pkr.getPublicKey();
            fail("Expected invalid algorythm. 'unknown' is not supported");
        } catch (IllegalStateException e) {
        }
    }

    @Test
    public void testGetFlags() {
        PublicKeyRecord pkr = new PublicKeyRecordImpl(
                "k=rsa; t=y:s; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIhyR3oItOy22ZOaBrIVe9m/iME3RqOJeasANSpg2YTHTYV+Xtp4xwf5gTjCmHQEMOs0qYu0FYiNQPQogJ2t0Mfx9zNu06rfRBDjiIU9tpx2T+NGlWZ8qhbiLo5By8apJavLyqTLavyPSrvsx0B3YzC63T4Age2CDqZYA+OwSMWQIDAQAB");
        pkr.validate();
        List<CharSequence> flags = pkr.getFlags();
        assertEquals("[y, s]", flags.toString());
        pkr = new PublicKeyRecordImpl(
                "k=rsa; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIhyR3oItOy22ZOaBrIVe9m/iME3RqOJeasANSpg2YTHTYV+Xtp4xwf5gTjCmHQEMOs0qYu0FYiNQPQogJ2t0Mfx9zNu06rfRBDjiIU9tpx2T+NGlWZ8qhbiLo5By8apJavLyqTLavyPSrvsx0B3YzC63T4Age2CDqZYA+OwSMWQIDAQAB");
        pkr.validate();
        flags = pkr.getFlags();
        assertEquals("[y]", flags.toString());
        pkr = new PublicKeyRecordImpl(
                "k=rsa; t=; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIhyR3oItOy22ZOaBrIVe9m/iME3RqOJeasANSpg2YTHTYV+Xtp4xwf5gTjCmHQEMOs0qYu0FYiNQPQogJ2t0Mfx9zNu06rfRBDjiIU9tpx2T+NGlWZ8qhbiLo5By8apJavLyqTLavyPSrvsx0B3YzC63T4Age2CDqZYA+OwSMWQIDAQAB");
        pkr.validate();
        flags = pkr.getFlags();
        assertEquals("[]", flags.toString());
    }

    @Test
    public void testIsTesting() {
        PublicKeyRecord pkr = new PublicKeyRecordImpl(
                "k=rsa; t=y:s; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIhyR3oItOy22ZOaBrIVe9m/iME3RqOJeasANSpg2YTHTYV+Xtp4xwf5gTjCmHQEMOs0qYu0FYiNQPQogJ2t0Mfx9zNu06rfRBDjiIU9tpx2T+NGlWZ8qhbiLo5By8apJavLyqTLavyPSrvsx0B3YzC63T4Age2CDqZYA+OwSMWQIDAQAB");
        pkr.validate();
        assertTrue(pkr.isTesting());
        pkr = new PublicKeyRecordImpl(
                "k=rsa; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIhyR3oItOy22ZOaBrIVe9m/iME3RqOJeasANSpg2YTHTYV+Xtp4xwf5gTjCmHQEMOs0qYu0FYiNQPQogJ2t0Mfx9zNu06rfRBDjiIU9tpx2T+NGlWZ8qhbiLo5By8apJavLyqTLavyPSrvsx0B3YzC63T4Age2CDqZYA+OwSMWQIDAQAB");
        pkr.validate();
        assertTrue(pkr.isTesting());
        pkr = new PublicKeyRecordImpl(
                "k=rsa; t=; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIhyR3oItOy22ZOaBrIVe9m/iME3RqOJeasANSpg2YTHTYV+Xtp4xwf5gTjCmHQEMOs0qYu0FYiNQPQogJ2t0Mfx9zNu06rfRBDjiIU9tpx2T+NGlWZ8qhbiLo5By8apJavLyqTLavyPSrvsx0B3YzC63T4Age2CDqZYA+OwSMWQIDAQAB");
        pkr.validate();
        assertFalse(pkr.isTesting());
    }

    @Test
    public void testIsDenySubdomains() {
        PublicKeyRecord pkr = new PublicKeyRecordImpl(
                "k=rsa; t=y:s; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIhyR3oItOy22ZOaBrIVe9m/iME3RqOJeasANSpg2YTHTYV+Xtp4xwf5gTjCmHQEMOs0qYu0FYiNQPQogJ2t0Mfx9zNu06rfRBDjiIU9tpx2T+NGlWZ8qhbiLo5By8apJavLyqTLavyPSrvsx0B3YzC63T4Age2CDqZYA+OwSMWQIDAQAB");
        pkr.validate();
        assertTrue(pkr.isDenySubdomains());
        pkr = new PublicKeyRecordImpl(
                "k=rsa; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIhyR3oItOy22ZOaBrIVe9m/iME3RqOJeasANSpg2YTHTYV+Xtp4xwf5gTjCmHQEMOs0qYu0FYiNQPQogJ2t0Mfx9zNu06rfRBDjiIU9tpx2T+NGlWZ8qhbiLo5By8apJavLyqTLavyPSrvsx0B3YzC63T4Age2CDqZYA+OwSMWQIDAQAB");
        pkr.validate();
        assertFalse(pkr.isDenySubdomains());
        pkr = new PublicKeyRecordImpl(
                "k=rsa; t=; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIhyR3oItOy22ZOaBrIVe9m/iME3RqOJeasANSpg2YTHTYV+Xtp4xwf5gTjCmHQEMOs0qYu0FYiNQPQogJ2t0Mfx9zNu06rfRBDjiIU9tpx2T+NGlWZ8qhbiLo5By8apJavLyqTLavyPSrvsx0B3YzC63T4Age2CDqZYA+OwSMWQIDAQAB");
        pkr.validate();
        assertFalse(pkr.isDenySubdomains());
    }

    @Test
    public void malformedKeyShouldThrowIllegalStateException() {
        PublicKeyRecordImpl record = new PublicKeyRecordImpl("v=DKIM1; k=rsa; p=AAAAA");

        assertThatThrownBy(record::getPublicKey).isInstanceOf(IllegalStateException.class);
    }

    @Test
    public void foldedKeyShouldDecode() throws Exception {
        String key = Base64.getEncoder().encodeToString(TestKeys.publicKey.getEncoded());
        String folded = key.substring(0, 10) + "\r\n " + key.substring(10, key.length() - 1) + " " + key.substring(key.length() - 1);

        assertEquals(TestKeys.publicKey, new PublicKeyRecordImpl("v=DKIM1; k=rsa; p=" + folded).getPublicKey());
    }

    @Test
    public void nonRsaKeyShouldThrowIllegalStateException() throws Exception {
        String ec = Base64.getEncoder().encodeToString(
                KeyPairGenerator.getInstance("EC").generateKeyPair().getPublic().getEncoded());

        assertThatThrownBy(new PublicKeyRecordImpl("v=DKIM1; k=EC; p=" + ec)::getPublicKey)
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(new PublicKeyRecordImpl("v=DKIM1; k=rsa; p=" + ec)::getPublicKey)
                .isInstanceOf(IllegalStateException.class);
    }

    private static final String P = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALgSoqXVSEmfcIsOzw7oRuCCOwsmtX/SJnTWxYyj2leFxfS/AVJ+dYfY+hXqMsT7l+MZvvh/R1WzN4MO/kI/7XsCAwEAAQ==";
    private static final SignatureRecord SIGN = new SignatureRecordImpl(
            "v=1; a=rsa-sha256; d=example.com; s=sel; h=from:to; bh=AAAA; b=AAAA");

    private static void applyRecord(String record) throws PermFailException {
        PublicKeyRecord pk = new DKIMVerifier().publicKeySelector(Collections.singletonList(record));
        DKIMVerifier.apply(pk, SIGN);
    }

    @Test
    public void keyRestrictedToAnotherServiceMustNotApplyToEmail() {
        for (String s : new String[] {"chat", "web", "web:chat"}) {
            try {
                applyRecord("v=DKIM1; s=" + s + "; p=" + P);
                fail("accepted s=" + s);
            } catch (PermFailException expected) {
            }
        }
    }

    @Test(expected = PermFailException.class)
    public void malformedServiceTypeListIsRejected() throws Exception {
        applyRecord("s=:email; p=" + P);
    }

    @Test
    public void malformedServiceTypeListIsAcceptedWithoutStrictValidation() throws Exception {
        System.setProperty(TagValue.STRICT_VALIDATION_PROPERTY, "false");
        try {
            applyRecord("s=:email; p=" + P);
        } finally {
            System.clearProperty(TagValue.STRICT_VALIDATION_PROPERTY);
        }
    }

    @Test(expected = PermFailException.class)
    public void otherServiceIsRejectedWithoutStrictValidation() throws Exception {
        System.setProperty(TagValue.STRICT_VALIDATION_PROPERTY, "false");
        try {
            applyRecord("s=chat; p=" + P);
        } finally {
            System.clearProperty(TagValue.STRICT_VALIDATION_PROPERTY);
        }
    }

    @Test
    public void emailAndWildcardServiceTypesApply() throws Exception {
        applyRecord("p=" + P);
        for (String s : new String[] {"*", "email", "web:email", "EMAIL", "email:web:fine", "web : email"}) {
            applyRecord("s=" + s + "; p=" + P);
        }
    }
}
