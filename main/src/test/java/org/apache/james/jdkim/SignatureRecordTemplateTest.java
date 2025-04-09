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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;

import org.apache.james.jdkim.api.HashMethod;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.api.SigningAlgorithm;
import org.apache.james.jdkim.tagvalue.SignatureRecordImpl;
import org.apache.james.jdkim.tagvalue.SignatureRecordTemplate;
import org.junit.Test;

public class SignatureRecordTemplateTest {

    // TODO check bytes > 128
    /*
     * public void test8bit() {
     * assertEquals("PROVA\144CIAO\144",Main.dkimQuotedPrintableDecode("PROVA=90CIAO=90")); }
     */
    @Test
    public void testBasic() {
        new SignatureRecordTemplate(
                "v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n"
                        + "        d=gmail.com; s=beta;\r\n"
                        + "        h=domainkey-signature:received:received:message-id:date:from:to:subject:mime-version:content-type;\r\n"
                        + "        bh=9sd6eO/xnGLInYGPFN86r9q27iClGpwfkl4PBc5XEuQ=;\r\n"
                        + "        b=tGQtBQg1sO+JKopOylApWLngylEqeMcXwCEUQN+S2PSpi9c1G9Nm5df9pMShus3iFaQb0PPvTfpw++cAC8/N0p3Gi/lVLc+Yh7xWEIPZ3Nxd3xqTQy7grIkBpV0q6559dEhhfFoEyLS0OK/IrqFIUVDRIMnsMjimXV7u+Sgoi7Q=");
    }

    @Test
    public void testWrongOrMissingVersion() {
        assertThatThrownBy(() ->
                new SignatureRecordTemplate(
                        "a=rsa-sha1; c=relaxed/relaxed;\r\n"
                                + "        d=gmail.com; s=beta;\r\n"
                                + "        h=domainkey-signature:received:received:message-id:date:from:to:subject:mime-version:content-type;\r\n"
                                + "        b=Kw/TqnjB4L5ZC7DX1ibiNkuIw630uHZvzuozn/e6yTm3U8ObWEz/rJK5GO8RSrF56JrCA/xo8W2CGmyNmpQYbEpLl5P9/NcJSYUmln/O6GSa4Usyv4FdEU4FVjkyW0ToGFHNkw9Mm0urveA4Lcfk9gClJczXnvGBdiv/bkVBEJk=")
        ).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("mandatory")
                .hasMessageContaining("v");
        assertThatThrownBy(() ->
                new SignatureRecordTemplate(
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
                new SignatureRecordTemplate(
                        "v=1; \r\n"
                                + "         s=beta;\r\n"
                                + "        h=domainkey-signature:received:received:message-id:date:from:to:subject:mime-version:content-type;\r\n"
                )
        ).isInstanceOf(IllegalStateException.class);
    }

    @Test
    public void testDomainMismatch() {
        assertThatThrownBy(() ->
                new SignatureRecordTemplate(
                        "v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n"
                                + "        d=gmail.com; s=beta; i=@agmail.com;\r\n"
                                + "        h=domainkey-signature:received:received:message-id:date:from:to:subject:mime-version:content-type;\r\n"
                                + "        bh=9sd6eO/xnGLInYGPFN86r9q27iClGpwfkl4PBc5XEuQ=;\r\n"
                                + "        b=tGQtBQg1sO+JKopOylApWLngylEqeMcXwCEUQN+S2PSpi9c1G9Nm5df9pMShus3iFaQb0PPvTfpw++cAC8/N0p3Gi/lVLc+Yh7xWEIPZ3Nxd3xqTQy7grIkBpV0q6559dEhhfFoEyLS0OK/IrqFIUVDRIMnsMjimXV7u+Sgoi7Q=")

        ).isInstanceOf(IllegalStateException.class);
    }

    @Test
    public void testMissingFrom() {
        assertThatThrownBy(() ->
                new SignatureRecordTemplate(
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
     * SignatureRecordTemplate("v=1; bh=0012=GG; b==GG;"); try { sr.getBodyHash();
     * fail("expected failure"); } catch (Exception e) {
     * assertTrue(e.getMessage().toLowerCase().contains("decod")); } try {
     * sr.getSignature(); fail("expected failure"); } catch (Exception e) {
     * assertTrue(e.getMessage().toLowerCase().contains("decod")); } }
     */

    @Test
    public void testWrongHashSyntaxes() {
        SignatureRecord sr = new SignatureRecordTemplate("v=1; a=nothyphenedword; bh=abcdef; b=1235345987; h=from:to; s=select; d=example.com");

        assertThatThrownBy(sr::getHashAlgo)
                .hasMessageContaining("hash");

        assertThatThrownBy(sr::getHashMethod)
                .hasMessageContaining("hash");
    }

    @Test
    public void testExpired() {
        assertThatThrownBy(() ->
                new SignatureRecordTemplate(
                        "v=1; c=simple; h=from:to; s=select; d=example.com; a=rsa-sha1; x=0; bh=abcdef; b=1235345987;"
                )
        ).hasMessageContaining("expired");
    }

    @Test
    public void should_return_a_full_signature_record_when_provided_the_signature() {
        SignatureRecordTemplate template = new SignatureRecordTemplate(
                "v=1; c=simple; h=from:to; s=select; d=example.com;"
        );

        byte[] bodyHash = "bodyHash".getBytes(StandardCharsets.UTF_8);
        byte[] signature = "signature".getBytes(StandardCharsets.UTF_8);
        SignatureRecordImpl signatureRecord = template.toSignatureRecord(
                SigningAlgorithm.RSA,
                HashMethod.SHA256,
                bodyHash,
                signature
        );


        assertThat(signatureRecord.getBodyHash()).isEqualTo(bodyHash);
        assertThat(signatureRecord.getSignature()).isEqualTo(signature);
    }
}
