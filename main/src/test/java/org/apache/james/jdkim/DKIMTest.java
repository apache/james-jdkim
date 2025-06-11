/******************************************************************************
 * Licensed to the Apache Software Foundation (ASF) under one                 *
 * or more contributor license agreements.  See the NOTICE file               *
 * distributed with this work for additional information                      *
 * regarding copyright ownership.  The ASF licenses this file                 *
 * to you under the Apache License, Version 2.0 (the                          *
 * "License"); you may not use this file except in compliance                 *
 * with the License.  You may obtain a copy of the License at                 *
 *                                                                            *
 *   http://www.apache.org/licenses/LICENSE-2.0                               *
 *                                                                            *
 * Unless required by applicable law or agreed to in writing,                 *
 * software distributed under the License is distributed on an                *
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY                     *
 * KIND, either express or implied.  See the License for the                  *
 * specific language governing permissions and limitations                    *
 * under the License.                                                         *
 ******************************************************************************/

package org.apache.james.jdkim;

import static java.util.stream.Collectors.joining;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import org.apache.commons.codec.binary.Base64;
import org.apache.james.jdkim.MockPublicKeyRecordRetriever.Record;
import org.apache.james.jdkim.api.Headers;
import org.apache.james.jdkim.api.Result;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.impl.Message;
import org.apache.james.jdkim.tagvalue.SignatureRecordTemplate;
import org.junit.Test;

public class DKIMTest {
    private final MockPublicKeyRecordRetriever keyRecordRetriever = new MockPublicKeyRecordRetriever(
            Record.of(
                    "selector2",
                    "messiah.edu",
                    "k=rsa; p=" + Base64.encodeBase64String(TestKeys.publicKey.getEncoded()) + ";"
            ),
            Record.of(
                    "selector3",
                    "messiah.edu",
                    "k=rsa; p=" + Base64.encodeBase64String(TestKeys.publicKey_2.getEncoded()) + ";"
            )
    );

    /**
     * - "a" field will be added by the signer based on signer setup
     * - "bh=" and "b=" placeholder are required for now because the same implementation is used for
     * signing and verifying. The fields are mandatory for verifying.
     */
    private static final String SIGNATURE_TEMPLATE = "v=1; c=simple; d=messiah.edu; h=date:from:subject; q=dns/txt; s=selector2;";
    private static final String SIGNATURE_TEMPLATE_2 = "v=1; a=rsa-sha1; c=simple; d=messiah.edu; h=date:from:subject; q=dns/txt; s=selector2;";
    private static final String SIGNATURE_TEMPLATE_3 = "v=1; a=rsa-sha256; c=simple; d=messiah.edu; h=date:from:subject; q=dns/txt; s=selector3;";

    private final DKIMSigner dkimSigner = new DKIMSigner();
    private final DKIMVerifier verifier = new DKIMVerifier(keyRecordRetriever);


    @Test
    public void should_verify_generated_signature_single_key() throws Exception {
        DkimSignatureHeader expectedSignature = new DkimSignatureHeader("a=rsa-sha256; q=dns/txt; b=Axa8s/gTnnJ8em45KV/AQw33hQ4uYtBKiQp3dLq7oRFt+WmDZ5ZErPq4lBVXfP+IAvP+Au91J8270ivn1J/6E0YqKntn4s1hjcNBPPRVohvmlcQ1mEMd6DuYDtWjDFwG2GWZwtilaPY2afhlTuAbHkn8nHm7MVtAGETO8QQ2zfD1NSGzKbNYP9I+hrDJq5ajka6PZn1d+mDhUH5Px8yScYqo5i8Z8GXaejSIu7RsLDuxtOO2cuClRi8MKGxc7MiGndMufXB8xbS1L80IFlyunOVY5eBaqnnhF2YrDDQfZ6DTqorzX6D5dNjpjOG6AbsqkW83Drx0TTV/5M0raU1SIw==; c=simple; s=selector2; d=messiah.edu; v=1; bh=6pQY5V6Dw8mCYWq017gfbpv+x2X4GvOhIIZtKw6iU6g=; h=date:from:subject;");

        SignatureRecordTemplate recordTemplate = new SignatureRecordTemplate(SIGNATURE_TEMPLATE);
        ByteArrayInputStream inputStream = readFileToByteArrayInputStream("/org/apache/james/jdkim/Mail-DKIM/corpus/multiple_2.txt");

        DkimSignatureHeader actualSignature = dkimSigner.sign(inputStream, recordTemplate, TestKeys.privateKey); // optional HashMethod parameter defaults to SHA-256

        // sanity check as it is very easy to change the bodyhash behaviour and thus break the signature
        assertEquals(expectedSignature, actualSignature);

        InputStream originalInputStream = readFileToByteArrayInputStream("/org/apache/james/jdkim/Mail-DKIM/corpus/multiple_2.txt");
        InputStream signatureInputStream = new ByteArrayInputStream((actualSignature.asMimeHeader() + "\r\n").getBytes(StandardCharsets.UTF_8));

        SequenceInputStream verifyInputStream = new SequenceInputStream(signatureInputStream, originalInputStream);
        DkimVerification dkimVerification = verifier.verify(verifyInputStream);

        assertThat(dkimVerification.isSuccess).isTrue();
        assertThat(dkimVerification.signatureVerifications)
                .hasSize(1)
                .allSatisfy(it ->
                        assertThat("DKIM-Signature:" + it.asHeaderString()).isEqualTo(expectedSignature)
                );

    }

    @Test
    public void should_verify_generated_signature_multiple_keys() throws Exception {
        // You might want to sign with multiple keys to support several hashmethods on the same selector
        // or several signing algorithm on the same selector ( ECDSA is a proposed alternative to rsa )
        // or when upgrading keys for any reason to add several signatures using different selectors.
        DkimSignatureHeader expectedSignature = new DkimSignatureHeader("a=rsa-sha256; q=dns/txt; b=Axa8s/gTnnJ8em45KV/AQw33hQ4uYtBKiQp3dLq7oRFt+WmDZ5ZErPq4lBVXfP+IAvP+Au91J8270ivn1J/6E0YqKntn4s1hjcNBPPRVohvmlcQ1mEMd6DuYDtWjDFwG2GWZwtilaPY2afhlTuAbHkn8nHm7MVtAGETO8QQ2zfD1NSGzKbNYP9I+hrDJq5ajka6PZn1d+mDhUH5Px8yScYqo5i8Z8GXaejSIu7RsLDuxtOO2cuClRi8MKGxc7MiGndMufXB8xbS1L80IFlyunOVY5eBaqnnhF2YrDDQfZ6DTqorzX6D5dNjpjOG6AbsqkW83Drx0TTV/5M0raU1SIw==; c=simple; s=selector2; d=messiah.edu; v=1; bh=6pQY5V6Dw8mCYWq017gfbpv+x2X4GvOhIIZtKw6iU6g=; h=date:from:subject;");
        DkimSignatureHeader expectedSignature2 = new DkimSignatureHeader("a=rsa-sha1; q=dns/txt; b=YiwcfjqM7myZ/OENExlyGVzy+rg/779R6pF7bPl79aL6e7yGYeN0XdLRcJEqhg+/uNFwcC7zrbWUwPBVFpFN8pKdQT7TgTr+ydoN65QiBa/rXH4m8Ga+oKx8652dXAHm9oMvG166VdMRsEKTJq2bFpM9RR4mW0KtHPte2JWiOtCYO6MPTlWA2JnIgQp+3+03rnOcKdQ+sn/bi9OwanwE4jgIBcPeHkHVr1fVsV53nvDlbk1DiDX+uOXvuk6bjPVBN4srZiSIvFKsmco0tGZx8cgs5OKyjmtIWVOvjxgupXWvEJJ1nMi1UQ1AXh6jDqWrMDCioRCMG9TeGy8fjcjcfw==; c=simple; s=selector2; d=messiah.edu; v=1; bh=q6DWKdHUzNbVPt6YBbD1KOai/b8=; h=date:from:subject;");
        DkimSignatureHeader expectedSignature3 = new DkimSignatureHeader("DKIM-Signature: a=rsa-sha256; q=dns/txt; b=crkBsqVuTJJmjZyNuJtmGXBsHIT7tJq0ONWLvNfO29sl1kNm9UzTZ4mOYR+akNJqonkaFFaVM9MZ/6QUd5NbGaIytxXnxv+NPNu6ZzUunlcRyOPhEQ/znemg3WjibRs24gWubBZZXApkqQ9kFh/atatoaJhTls/lnbP8ZV3XlWVN12UuESU3qdieRvrhKWX5/Od7LqZS04ZTeToAabOtDmm6hYl2R6wxizdHrOkGiNERfbB8Iaws5f3Qnt0S94wQ5FVTPzgRiO9OW8hYbAijS4Bh8/NXV5xauMXjCETfxX3pQYUuxc4QVhnoMbmuqgEulzuJUzapjotLLFxQRaSsjw==; c=simple; s=selector3; d=messiah.edu; v=1; bh=6pQY5V6Dw8mCYWq017gfbpv+x2X4GvOhIIZtKw6iU6g=; h=date:from:subject;");

        ByteArrayInputStream inputStream1 = readFileToByteArrayInputStream("/org/apache/james/jdkim/Mail-DKIM/corpus/multiple_2.txt");
        String actualSignature1 = dkimSigner.sign(inputStream1);
        ByteArrayInputStream inputStream2 = readFileToByteArrayInputStream("/org/apache/james/jdkim/Mail-DKIM/corpus/multiple_2.txt");
        DKIMSigner signer2 = new DKIMSigner(SIGNATURE_TEMPLATE_2, TestKeys.privateKey);
        String actualSignature2 = signer2.sign(inputStream2);
        ByteArrayInputStream inputStream3 = readFileToByteArrayInputStream("/org/apache/james/jdkim/Mail-DKIM/corpus/multiple_2.txt");
        DKIMSigner signer3 = new DKIMSigner(SIGNATURE_TEMPLATE_3, TestKeys.privateKey_2);
        String actualSignature3 = signer3.sign(inputStream3);

        // sanity check as it is very easy to change the bodyhash behaviour and thus break the signature
        assertEquals(expectedSignature, actualSignature1);
        assertEquals(expectedSignature2, actualSignature2);
        assertEquals(expectedSignature3, actualSignature3);

        // prepend signatures to the message as per https://datatracker.ietf.org/doc/html/rfc6376#section-3.5
        InputStream originalInputStream = readFileToByteArrayInputStream("/org/apache/james/jdkim/Mail-DKIM/corpus/multiple_2.txt");
        String signatures = String.join("\r\n", Arrays.asList(actualSignature1, actualSignature2, actualSignature3));
        InputStream signatureInputStream = new ByteArrayInputStream((signatures + "\r\n").getBytes(StandardCharsets.UTF_8));

        SequenceInputStream verifyInputStream = new SequenceInputStream(signatureInputStream, originalInputStream);

        List<SignatureRecord> verifiedSignatures = verifier.verify(verifyInputStream);

        List<Result> results = verifier.getResults();
        assertThat(results)
                .filteredOn(Result::isSuccess)
                .hasSize(3)
                .allSatisfy(it ->
                        assertThat(it.getRecord().getSelector()).isIn("selector2", "selector3")
                )
        ;
        assertThat(verifiedSignatures)
                .hasSize(3)
                .satisfiesOnlyOnce(it ->
                        assertThat("DKIM-Signature:" + it.toString()).isEqualTo(expectedSignature)
                ).satisfiesOnlyOnce(it ->
                        assertThat("DKIM-Signature:" + it.toString()).isEqualTo(expectedSignature2)
                ).satisfiesOnlyOnce(it ->
                        assertThat("DKIM-Signature:" + it.toString()).isEqualTo(expectedSignature3)
                );

    }


    private ByteArrayInputStream readFileToByteArrayInputStream(String fileName) throws URISyntaxException, IOException {
        URL resource = this.getClass().getResource(fileName);
        FileInputStream file = new FileInputStream(new File(resource.toURI()));
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        DKIMCommon.streamCopy(file, byteArrayOutputStream);
        String string = byteArrayOutputStream.toString();
        return new ByteArrayInputStream(string.getBytes(StandardCharsets.UTF_8));
    }

    private static class HeaderSignatureOverride implements Headers {
        private final Message headers;
        private final List<String> dkimSignatures;

        public HeaderSignatureOverride(Message headers, List<String> signatures) {
            this.headers = headers;
            this.dkimSignatures = signatures;
        }

        @Override
        public List<String> getFields() {
            return headers.getFields();
        }

        @Override
        public List<String> getFields(String name) {
            if ("DKIM-Signature".equals(name)) {
                return dkimSignatures;
            } else {
                return headers.getFields(name);
            }
        }

        public InputStream getBodyInputStream() {
            return headers.getBodyInputStream();
        }
    }

    // ======== IGNORE CODE BELOW THIS FOR STARTERS ====== //

    private static class DkimSignatureHeader {
        private final String name = "DKIM-Signature";
        private final String value;

        private DkimSignatureHeader(String value) {
            this.value = value;
        }

        public String asMimeHeader() {
            return name + ": " + value;
        }

        @Override
        public boolean equals(Object o) {
            if (o == null || getClass() != o.getClass()) return false;
            DkimSignatureHeader that = (DkimSignatureHeader) o;
            return Objects.equals(name, that.name) && Objects.equals(value, that.value);
        }

        @Override
        public int hashCode() {
            return Objects.hash(name, value);
        }
    }

    /**
     * source https://datatracker.ietf.org/doc/html/rfc8601#section-2.7.1
     */
    private static enum SignatureVerificationResult {
        // NONE means The message was not signed so it cannot be a signature result.
        /**
         * The message was signed, the signature or signatures were acceptable
         * to the ADMD, and the signature(s) passed verification tests.
         */
        PASS,
        /**
         * The message was signed and the signature or signatures were
         * acceptable to the ADMD, but they failed the verification test(s).
         */
        FAIL,
        /**
         * The message was signed, but some aspect of the signature or
         * signatures was not acceptable to the ADMD.
         */
        POLICY,
        /**
         * The message was signed, but the signature or signatures contained
         * syntax errors or were not otherwise able to be processed.
         * This result is also used for other failures not covered elsewhere
         * in this list.
         */
        NEUTRAL,
        /**
         * The message could not be verified due to some error th   at is likely
         * transient in nature, such as a temporary inability to retrieve a
         * public key.
         * A later attempt may produce a final result.
         */
        TEMPFAIL,
        /**
         * The message could not be verified due to some error that is
         * unrecoverable, such as a required header field being absent.
         * A later attempt is unlikely to produce a final result.
         */
        PERMFAIL
    }

    private enum FailedHeaderTagName {
        SIGNING_DOMAIN("header.d"),
        IDENTITY("header.i"),
        ALGORITHM("header.a"),
        SELECTOR("header.s");

        private final String value;

        FailedHeaderTagName(String value) {
            this.value = value;
        }
    }

    private static class FailedHeaderTag {
        private final FailedHeaderTagName tagName;
        private final String value;

        private FailedHeaderTag(FailedHeaderTagName tagName, String value) {
            this.tagName = tagName;
            this.value = value;
        }

        public String asHeaderString() {
            return tagName.value + "=" + value + ";";
        }
    }

    private static class SignatureVerification {
        private final SignatureVerificationResult result;
        private final Optional<String> reason;
        private final Optional<FailedHeaderTag> tag;

        private SignatureVerification(
                SignatureVerificationResult result,
                Optional<String> reason,
                Optional<FailedHeaderTag> tag
        ) {
            this.result = result;
            this.reason = reason;
            this.tag = tag;
        }

        String asHeaderString() {
            String reason = this.reason.map(it -> "reason=" + it).orElse("");
            String tag = this.tag.map(FailedHeaderTag::asHeaderString).orElse("");

            switch (result) {
                case PASS:
                    return "dkim=pass (good signature);";
                case FAIL:
                    return Stream.of("dkim=fail", reason, tag)
                            .filter(it->!it.isEmpty())
                            .collect(joining("", " ", ";"));
                case POLICY:
                    return Stream.of("dkim=policy", reason, tag)
                            .filter(it->!it.isEmpty())
                            .collect(joining("", " ", ";"));
                case NEUTRAL:
                    return Stream.of("dkim=neutral", reason, tag)
                            .filter(it->!it.isEmpty())
                            .collect(joining("", " ", ";"));
                case TEMPFAIL:
                    return Stream.of("dkim=temperror", reason, tag)
                            .filter(it->!it.isEmpty())
                            .collect(joining("", " ", ";"));
                case PERMFAIL:
                    return Stream.of("dkim=permerror", reason, tag)
                            .filter(it->!it.isEmpty())
                            .collect(joining("", " ", ";"));
                default:
                    throw new IllegalStateException("unreachable code, which will disappear in later java versions with exhaustivity checking");
            }
        }
    }

    private static class DkimVerification {
        private final List<SignatureVerification> signatureVerifications;
        boolean isSuccess;

        private DkimVerification(List<SignatureVerification> signatureVerifications) {
            this.signatureVerifications = signatureVerifications;
            isSuccess = signatureVerifications.stream()
                    .anyMatch(it ->
                            it.result == SignatureVerificationResult.PASS
                    );
        }

        String asHeaderString() {
            return signatureVerifications.stream()
                    .map(it ->
                            it.asHeaderString()).collect(joining(";\r\n")
                    );
        }
    }
}