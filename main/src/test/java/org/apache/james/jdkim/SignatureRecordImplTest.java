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

import org.apache.james.jdkim.tagvalue.PublicKeyRecordImpl;
import org.apache.james.jdkim.tagvalue.SignatureRecordTemplate;
import java.util.Locale;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.tagvalue.SignatureRecordImpl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;

public class SignatureRecordImplTest {
    @Test
    public void testBasic() {
        new SignatureRecordImpl(
                "v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n"
                        + "        d=gmail.com; s=beta;\r\n"
                        + "        h=domainkey-signature:received:received:message-id:date:from:to:subject:mime-version:content-type;\r\n"
                        + "        bh=9sd6eO/xnGLInYGPFN86r9q27iClGpwfkl4PBc5XEuQ=;\r\n"
                        + "        b=tGQtBQg1sO+JKopOylApWLngylEqeMcXwCEUQN+S2PSpi9c1G9Nm5df9pMShus3iFaQb0PPvTfpw++cAC8/N0p3Gi/lVLc+Yh7xWEIPZ3Nxd3xqTQy7grIkBpV0q6559dEhhfFoEyLS0OK/IrqFIUVDRIMnsMjimXV7u+Sgoi7Q=");

    }

    @Test
    public void testWrongOrMissingVersion() {
        assertThatThrownBy(() ->
                new SignatureRecordImpl(
                        "a=rsa-sha1; c=relaxed/relaxed;\r\n"
                                + "        d=gmail.com; s=beta;\r\n"
                                + "        h=domainkey-signature:received:received:message-id:date:from:to:subject:mime-version:content-type;\r\n"
                                + "        b=Kw/TqnjB4L5ZC7DX1ibiNkuIw630uHZvzuozn/e6yTm3U8ObWEz/rJK5GO8RSrF56JrCA/xo8W2CGmyNmpQYbEpLl5P9/NcJSYUmln/O6GSa4Usyv4FdEU4FVjkyW0ToGFHNkw9Mm0urveA4Lcfk9gClJczXnvGBdiv/bkVBEJk=")
        ).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("mandatory")
                .hasMessageContaining("v");
        assertThatThrownBy(() ->
                new SignatureRecordImpl(
                        "v=2; a=rsa-sha256; c=relaxed/relaxed;\r\n"
                                + "        d=gmail.com; s=beta;\r\n"
                                + "        h=domainkey-signature:received:received:message-id:date:from:to:subject:mime-version:content-type;\r\n"
                                + "        bh=9sd6eO/xnGLInYGPFN86r9q27iClGpwfkl4PBc5XEuQ=;\r\n"
                                + "        b=tGQtBQg1sO+JKopOylApWLngylEqeMcXwCEUQN+S2PSpi9c1G9Nm5df9pMShus3iFaQb0PPvTfpw++cAC8/N0p3Gi/lVLc+Yh7xWEIPZ3Nxd3xqTQy7grIkBpV0q6559dEhhfFoEyLS0OK/IrqFIUVDRIMnsMjimXV7u+Sgoi7Q=")
        ).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Invalid")
                .hasMessageContaining("version")
                .hasMessageContaining("2");
    }

    @Test
    public void testMissingRequired() {
        assertThatThrownBy(() ->
            new SignatureRecordImpl(
                    "v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n"
                            + "        d=gmail.com; s=beta;\r\n"
                            + "        h=domainkey-signature:received:received:message-id:date:from:to:subject:mime-version:content-type;\r\n"
                            + "        b=tGQtBQg1sO+JKopOylApWLngylEqeMcXwCEUQN+S2PSpi9c1G9Nm5df9pMShus3iFaQb0PPvTfpw++cAC8/N0p3Gi/lVLc+Yh7xWEIPZ3Nxd3xqTQy7grIkBpV0q6559dEhhfFoEyLS0OK/IrqFIUVDRIMnsMjimXV7u+Sgoi7Q=")
        ).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("mandatory")
                .hasMessageContaining("bh");
    }

    @Test
    public void testDomainMismatch() {
        assertThatThrownBy(() ->
                new SignatureRecordImpl(
                        "v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n"
                                + "        d=gmail.com; s=beta; i=@agmail.com;\r\n"
                                + "        h=domainkey-signature:received:received:message-id:date:from:to:subject:mime-version:content-type;\r\n"
                                + "        bh=9sd6eO/xnGLInYGPFN86r9q27iClGpwfkl4PBc5XEuQ=;\r\n"
                                + "        b=tGQtBQg1sO+JKopOylApWLngylEqeMcXwCEUQN+S2PSpi9c1G9Nm5df9pMShus3iFaQb0PPvTfpw++cAC8/N0p3Gi/lVLc+Yh7xWEIPZ3Nxd3xqTQy7grIkBpV0q6559dEhhfFoEyLS0OK/IrqFIUVDRIMnsMjimXV7u+Sgoi7Q=")
        ).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("domain mismatch");
    }

    @Test
    public void testMissingFrom() {
        assertThatThrownBy(() ->
                new SignatureRecordImpl(
                        "v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n"
                                + "        d=gmail.com; s=beta; i=@subdomain.gmail.com;\r\n"
                                + "        h=domainkey-signature:received:received:message-id:date:fram:to:subject:mime-version:content-type;\r\n"
                                + "        bh=9sd6eO/xnGLInYGPFN86r9q27iClGpwfkl4PBc5XEuQ=;\r\n"
                                + "        b=tGQtBQg1sO+JKopOylApWLngylEqeMcXwCEUQN+S2PSpi9c1G9Nm5df9pMShus3iFaQb0PPvTfpw++cAC8/N0p3Gi/lVLc+Yh7xWEIPZ3Nxd3xqTQy7grIkBpV0q6559dEhhfFoEyLS0OK/IrqFIUVDRIMnsMjimXV7u+Sgoi7Q=")
        ).isInstanceOf(IllegalStateException.class)
                .hasMessage("From field not signed");
    }


    /*
     * when we moved from Sun's Base64 to CommonsCodec the decoding changed
     * behaviour. it does no more fail on bad encoded data. public void
     * testWrongBase64Encoding() { SignatureRecord sr = new
     * SignatureRecordImpl("v=1; bh=0012=GG; b==GG;"); try { sr.getBodyHash();
     * fail("expected failure"); } catch (Exception e) {
     * assertTrue(e.getMessage().toLowerCase().contains("decod")); } try {
     * sr.getSignature(); fail("expected failure"); } catch (Exception e) {
     * assertTrue(e.getMessage().toLowerCase().contains("decod")); } }
     */

    @Test
    public void testWrongHashSyntaxes() {
        assertThatThrownBy(() -> new SignatureRecordImpl("v=1; a=nothyphenedword; bh=abcdef; b=1235345987; h=from:to; s=select; d=example.com"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("algorithm");
    }

    @Test
    public void algorithmsOutsideRfc6376ShouldBeRejected() {
        for (String a : new String[] {"rsa-md5", "rsa-md2", "rsa-sha512/256", "rsa-sha512", "rsa-sha384", "rsa-sha224",
                "rsa-SHA256", "RSA-SHA256", "Rsa-Sha1", "dsa-sha256", "rsa-sha3-256"}) {
            assertThatThrownBy(() -> new SignatureRecordImpl("v=1; a=" + a + "; bh=abcdef; b=1235345987; h=from:to; s=select; d=example.com"))
                    .as("a=%s", a)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("algorithm");
        }
        new SignatureRecordImpl("v=1; a=rsa-sha256; bh=abcdef; b=1235345987; h=from:to; s=select; d=example.com");
        new SignatureRecordImpl("v=1; a=rsa-sha1; bh=abcdef; b=1235345987; h=from:to; s=select; d=example.com");
    }

    @Test
    public void testExpired() {
        assertThatThrownBy(() ->
                new SignatureRecordImpl(
                        "v=1; c=simple; h=from:to; s=select; d=example.com; a=rsa-sha1; x=0; bh=abcdef; b=1235345987;"
                )
        ).hasMessageContaining("expired");
    }

    @Test
    public void should_parse_signature_with_newline_between_padding() {
        String signature = "v=1; a=rsa-sha256; q=dns/txt; c=simple; s=selector2; d=messiah.edu; bh=6pQY\r\n" +
                "    5V6Dw8mCYWq017gfbpv+x2X4GvOhIIZtKw6iU6g=; h=date:from:subject; b=Axa\r\n" +
                "    8s/gTnnJ8em45KV/AQw33hQ4uYtBKiQp3dLq7oRFt+WmDZ5ZErPq4lBVXfP+IAvP+Au9\r\n" +
                "    1J8270ivn1J/6E0YqKntn4s1hjcNBPPRVohvmlcQ1mEMd6DuYDtWjDFwG2GWZwtilaPY\r\n" +
                "    2afhlTuAbHkn8nHm7MVtAGETO8QQ2zfD1NSGzKbNYP9I+hrDJq5ajka6PZn1d+mDhUH5\r\n" +
                "    Px8yScYqo5i8Z8GXaejSIu7RsLDuxtOO2cuClRi8MKGxc7MiGndMufXB8xbS1L80IFly\r\n" +
                "    unOVY5eBaqnnhF2YrDDQfZ6DTqorzX6D5dNjpjOG6AbsqkW83Drx0TTV/5M0raU1SIw=\r\n" +
                "    =";

        SignatureRecordImpl signatureRecord = new SignatureRecordImpl(signature);
        Assert.assertTrue(signatureRecord.getSignature().length > 0);
        Assert.assertTrue(signatureRecord.getBodyHash().length > 0);
    }

    @Test
    public void settersShouldRoundTripRawBytes() {
        SignatureRecordImpl record = new SignatureRecordImpl("v=1; a=rsa-sha256; d=example.com; s=s; h=from; bh=AA==; b=AA==");
        byte[] digest = new byte[32];
        byte[] signature = {0, 1, 2, (byte) 0xff, 0x3d};
        Arrays.fill(digest, (byte) 0x08);

        record.setBodyHash(digest);
        record.setSignature(signature);

        assertThat(record.getBodyHash()).isEqualTo(digest);
        assertThat(record.getSignature()).isEqualTo(signature);
        assertThat(new SignatureRecordImpl(record.toString()).getSignature()).isEqualTo(signature);
    }

    @Test
    public void nonNumericExpirationShouldBeASyntaxError() {
        String base = "v=1; a=rsa-sha256; d=example.com; s=s; h=from; bh=AA==; b=AA==; ";

        assertThatThrownBy(() -> new SignatureRecordImpl(base + "x="))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new SignatureRecordImpl(base + "x=abc"))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new SignatureRecordImpl(base + "x=9999999999999"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    public void nonNumericTimestampShouldBeASyntaxError() {
        String base = "v=1; a=rsa-sha256; d=example.com; s=s; h=from; bh=AA==; b=AA==; ";

        assertThatThrownBy(() -> new SignatureRecordImpl(base + "t="))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new SignatureRecordImpl(base + "t=-"))
                .isInstanceOf(IllegalStateException.class);
        assertThat(new SignatureRecordImpl(base + "t=1234567890").getSignatureTimestamp()).isEqualTo(1234567890L);
    }

    @Test
    public void nonNumericBodyLengthShouldBeASyntaxError() {
        String base = "v=1; a=rsa-sha256; d=example.com; s=s; h=from; bh=AA==; b=AA==; ";

        assertThatThrownBy(() -> new SignatureRecordImpl(base + "l="))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new SignatureRecordImpl(base + "l=a"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    public void signedBodyLengthShouldBeASyntaxError() {
        String base = "v=1; a=rsa-sha256; d=example.com; s=s; h=from; bh=AA==; b=AA==; ";

        assertThatThrownBy(() -> new SignatureRecordImpl(base + "l=-1")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new SignatureRecordImpl(base + "l=-5")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new SignatureRecordImpl(base + "l=+5")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new SignatureRecordImpl(base + "l=-0")).isInstanceOf(IllegalStateException.class);
    }

    @Test
    public void bodyLengthBeyondIntegerRangeShouldBeClamped() {
        String base = "v=1; a=rsa-sha256; d=example.com; s=s; h=from; bh=AA==; b=AA==; ";

        assertThat(new SignatureRecordImpl(base + "l=99999999999").getBodyHashLimit()).isEqualTo(Integer.MAX_VALUE);
        assertThat(new SignatureRecordImpl(base + "l=0000000000000000042").getBodyHashLimit()).isEqualTo(42);
        assertThat(new SignatureRecordImpl(base + "l=0").getBodyHashLimit()).isEqualTo(0);
    }

    @Test
    public void identityWithoutExactlyOneAtShouldBeRejected() {
        String base = "v=1; a=rsa-sha256; d=example.com; s=s; h=from; bh=AA==; b=AA==; ";

        assertThatThrownBy(() -> new SignatureRecordImpl(base + "i=.example.com"))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new SignatureRecordImpl(base + "i==40@example.com"))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new SignatureRecordImpl(base + "i=joe@badexample.com"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    public void identityInDomainOrSubdomainShouldBeAccepted() {
        String base = "v=1; a=rsa-sha256; d=example.com; s=s; h=from; bh=AA==; b=AA==; ";

        assertThat(new SignatureRecordImpl(base + "i=joe@Example.COM").getIdentityLocalPart()).isEqualTo("joe");
        assertThat(new SignatureRecordImpl(base + "i=@mail.example.com").getIdentityLocalPart()).isEqualTo("");
    }

    @Test
    public void identityCheckShouldNotDependOnTheDefaultLocale() throws Exception {
        Locale saved = Locale.getDefault();
        Locale.setDefault(Locale.forLanguageTag("tr-TR"));
        try {
            new SignatureRecordTemplate("v=1; s=sel; d=Mail.Example.Com; a=rsa-sha256; h=from; i=@MAIL.EXAMPLE.COM");
            SignatureRecordImpl sign = new SignatureRecordImpl("v=1; s=sel; d=Mail.Example.Com; a=rsa-sha256; h=from; bh=AA==; b=AA==; i=@MAIL.EXAMPLE.COM");
            DKIMVerifier.apply(new PublicKeyRecordImpl("v=DKIM1; k=rsa; t=s; p=AAAA"), sign);
        } finally {
            Locale.setDefault(saved);
        }
    }

    @Test
    public void signatureWithCharactersOutsideTheBase64AlphabetShouldNotDecode() {
        SignatureRecordImpl record = new SignatureRecordImpl(
                "v=1; a=rsa-sha256; d=example.com; s=s; h=from; bh=AA==; b=AA.AA");

        assertThatThrownBy(record::getSignature).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void bodyHashWithDataAfterThePaddingShouldNotDecode() {
        SignatureRecordImpl record = new SignatureRecordImpl(
                "v=1; a=rsa-sha256; d=example.com; s=s; h=from; bh= AA== === ; b=AA==");

        assertThatThrownBy(record::getBodyHash).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void base64FoldedBetweenThePaddingCharactersShouldDecode() {
        SignatureRecordImpl record = new SignatureRecordImpl(
                "v=1; a=rsa-sha256; d=example.com; s=s; h=from; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU\r\n =; b=AA= =");

        assertThat(record.getBodyHash()).hasSize(32);
        assertThat(record.getSignature()).containsExactly(0);
    }

    @Test
    public void toUnsignedStringShouldEmptyOnlyTheBTag() {
        assertThat(new SignatureRecordImpl("v=1; a=rsa-sha256; d=example.com; s=s; h=from; bh=AA==; xb=1; b=AA==").toUnsignedString())
                .isEqualTo("v=1; a=rsa-sha256; d=example.com; s=s; h=from; bh=AA==; xb=1; b=");
        assertThat(new SignatureRecordImpl("v=1; b = AA\r\n BB ; a=rsa-sha256; d=example.com; s=s; h=from:b=:x; bh=AA==").toUnsignedString())
                .isEqualTo("v=1; b =; a=rsa-sha256; d=example.com; s=s; h=from:b=:x; bh=AA==");
    }

    @Test
    public void expirationNotAfterTimestampShouldBeRejected() {
        long now = System.currentTimeMillis() / 1000;
        String base = "v=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=AA==; b=AA==; ";

        assertThatThrownBy(() -> new SignatureRecordImpl(base + "t=" + (now + 1000) + "; x=" + (now + 500)))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new SignatureRecordImpl(base + "t=" + (now + 1000) + "; x=" + (now + 1000)))
                .isInstanceOf(IllegalStateException.class);
        // x= after t= stays valid
        new SignatureRecordImpl(base + "t=" + now + "; x=" + (now + 1000));
    }
}
