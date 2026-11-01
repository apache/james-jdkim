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

import org.apache.james.jdkim.api.BodyHasher;
import java.util.stream.Collectors;
import org.apache.james.mime4j.MimeException;
import java.security.MessageDigest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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
import java.security.Signature;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.james.jdkim.MockPublicKeyRecordRetriever.Record;
import org.apache.james.jdkim.api.Headers;
import org.apache.james.jdkim.api.Result;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.api.UnsignedDuplicateFieldPolicy;
import org.apache.james.jdkim.api.VerifierOptions;
import org.apache.james.jdkim.exceptions.FailException;
import org.apache.james.jdkim.exceptions.CompositeFailException;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.impl.Message;
import org.apache.james.jdkim.tagvalue.SignatureRecordImpl;
import org.junit.Test;

public class DKIMTest {
    private final MockPublicKeyRecordRetriever keyRecordRetriever = new MockPublicKeyRecordRetriever(
            Record.of(
                    "selector2",
                    "messiah.edu",
                    "k=rsa; p=" + Base64.getEncoder().encodeToString(TestKeys.publicKey.getEncoded()) + ";"
            ),
            Record.of(
                    "selector3",
                    "messiah.edu",
                    "k=rsa; p=" + Base64.getEncoder().encodeToString(TestKeys.publicKey_2.getEncoded()) + ";"
            )
    );

    /**
     * - "a" field will be added by the signer based on signer setup
     * - "bh=" and "b=" placeholder are required for now because the same implementation is used for
     * signing and verifying. The fields are mandatory for verifying.
     */
    private static final String SIGNATURE_TEMPLATE = "v=1; a=rsa-sha256; c=simple; d=messiah.edu; h=date:from:subject; q=dns/txt; s=selector2;";
    private static final String SIGNATURE_TEMPLATE_2 = "v=1; a=rsa-sha1; c=simple; d=messiah.edu; h=date:from:subject; q=dns/txt; s=selector2;";
    private static final String SIGNATURE_TEMPLATE_3 = "v=1; a=rsa-sha256; c=simple; d=messiah.edu; h=date:from:subject; q=dns/txt; s=selector3;";

    private final DKIMSigner dkimSigner = new DKIMSigner(SIGNATURE_TEMPLATE, TestKeys.privateKey);
    private final DKIMVerifier verifier = new DKIMVerifier(new VerifierOptions.Builder().withPublicKeyRecordRetriever(keyRecordRetriever).build());

    @Test
    public void should_verify_generated_signature_single_key() throws Exception {
        String expectedSignature = "DKIM-Signature: a=rsa-sha256; q=dns/txt; b=\r\n"
                + " C+1++2C84m11IB3g95xLH9fMGUC/eDf8hzv267Htlr010KmPOa+ljSTVGzWUnsor9JXIDXwl\r\n"
                + " a7JEMixM5GRDhmZX/bkHki3BBkyjQxOq7g8YNfMIOE0igpM2j6kItCP6fA9jAG7mBfHFOwiu\r\n"
                + " a2pxXzejH3mxefUK2RfQ93aFG3Mm0BWMTkkEr0km6+M4crjuDj63+od4lmXMu8PEkirSAERH\r\n"
                + " CzpIfluJpl/TfEhQ9kMljPaAFApt1iLzaIPyOTIUQx+pWRbuVGE52+Z+Sbco1m/1+9gKWyk7\r\n"
                + " S9flEbozdtNIadQSOfhcl+wMaG/R8Y7166HilWhzz9uF6u7gv/VIMQ==;\r\n"
                + " c=simple; s=selector2; d=messiah.edu; v=1;\r\n"
                + " bh=6pQY5V6Dw8mCYWq017gfbpv+x2X4GvOhIIZtKw6iU6g=; h=date:from:subject;";

        ByteArrayInputStream inputStream = readFileToByteArrayInputStream("/org/apache/james/jdkim/Mail-DKIM/corpus/multiple_2.txt");
        String actualSignature = dkimSigner.sign(inputStream);

        // sanity check as it is very easy to change the bodyhash behaviour and thus break the signature
        assertEquals(expectedSignature, actualSignature);

        InputStream originalInputStream = readFileToByteArrayInputStream("/org/apache/james/jdkim/Mail-DKIM/corpus/multiple_2.txt");
        InputStream signatureInputStream = new ByteArrayInputStream((actualSignature + "\r\n").getBytes(StandardCharsets.UTF_8));

        SequenceInputStream verifyInputStream = new SequenceInputStream(signatureInputStream, originalInputStream);
        List<SignatureRecord> verifiedSignatures = verifier.verify(verifyInputStream);

        assertThat(verifiedSignatures)
                .hasSize(1)
                .allSatisfy(it ->
                        assertThat("DKIM-Signature:" + it.toString()).isEqualTo(expectedSignature)
                );

    }

    @Test
    public void should_verify_generated_signature_multiple_keys() throws Exception {
        // You might want to sign with multiple keys to support several hashmethods on the same selector
        // or several signing algorithm on the same selector ( ECDSA is a proposed alternative to rsa )
        // or when upgrading keys for any reason to add several signatures using different selectors.
        String expectedSignature = "DKIM-Signature: a=rsa-sha256; q=dns/txt; b=\r\n"
                + " C+1++2C84m11IB3g95xLH9fMGUC/eDf8hzv267Htlr010KmPOa+ljSTVGzWUnsor9JXIDXwl\r\n"
                + " a7JEMixM5GRDhmZX/bkHki3BBkyjQxOq7g8YNfMIOE0igpM2j6kItCP6fA9jAG7mBfHFOwiu\r\n"
                + " a2pxXzejH3mxefUK2RfQ93aFG3Mm0BWMTkkEr0km6+M4crjuDj63+od4lmXMu8PEkirSAERH\r\n"
                + " CzpIfluJpl/TfEhQ9kMljPaAFApt1iLzaIPyOTIUQx+pWRbuVGE52+Z+Sbco1m/1+9gKWyk7\r\n"
                + " S9flEbozdtNIadQSOfhcl+wMaG/R8Y7166HilWhzz9uF6u7gv/VIMQ==;\r\n"
                + " c=simple; s=selector2; d=messiah.edu; v=1;\r\n"
                + " bh=6pQY5V6Dw8mCYWq017gfbpv+x2X4GvOhIIZtKw6iU6g=; h=date:from:subject;";
        String expectedSignature2 = "DKIM-Signature: a=rsa-sha1; q=dns/txt; b=\r\n"
                + " KZAV2MxR3rpgiMusBSzFlMX2AdiloPGzz1nwSFN3XCZf3negA5PePSbHzB+49ZI0guESW1tJ\r\n"
                + " qhs5ke3lSTq/06B6y6AIreAVneZMetOlZQT6iKYWSkKJLrXB/lQMDWjsy73X8aiaVXCpnAY0\r\n"
                + " IKy5YHNZe0deFEsiVf6ooXGxxm3ZkDNJx4kFM+LO+Cc4SXSj+XbN9U32WPMb6NwMYGt/3JqC\r\n"
                + " Efp33mQSM8kktisvNiNOVMLAcDH7JsxL+ZvMhcyR9ysoyxZYbA3YjiGplrawANQhOBMmskjt\r\n"
                + " dbtMy80J1vYK/7QHqr/k1jvSexSXtqENKdsdhSRvFYn0zZVE5RF64w==;\r\n"
                + " c=simple; s=selector2; d=messiah.edu; v=1; bh=q6DWKdHUzNbVPt6YBbD1KOai/b8=;\r\n"
                + " h=date:from:subject;";
        String expectedSignature3 = "DKIM-Signature: a=rsa-sha256; q=dns/txt; b=\r\n"
                + " UtvF5klyckyu+x/qq5QWauomFRNMBYjt5ozWB4k7wWAolnhbgWZ2pwfdnkjygJxqwWpb8YQr\r\n"
                + " M9oM1umMc+Lh1icGMzRERkADy1EMHFrhxMfjLsu8tnU2A23Z+Pjc9ZSuLJIelPoPZt8cZNX6\r\n"
                + " aEkLBm/PFy8mct0FMsZGTJEQKAOOLwpKk2XLEaGdgsCY8C11BHIyKP5ahx53neAQFot299qx\r\n"
                + " /4274+v/0ydPtHDJO007s3QTbHJbhcIsWzGwTCY/Ukx4lqSg+9COTFqVlTcF20HvB9Vm6DUi\r\n"
                + " xFSaocxZmja2yewLh4+QPSqU2m3j7W6v7BkPYOqpQCeBy39SOU3rDw==;\r\n"
                + " c=simple; s=selector3; d=messiah.edu; v=1;\r\n"
                + " bh=6pQY5V6Dw8mCYWq017gfbpv+x2X4GvOhIIZtKw6iU6g=; h=date:from:subject;";

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
        InputStream signatureInputStream = new ByteArrayInputStream((signatures+"\r\n").getBytes(StandardCharsets.UTF_8));

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

    @Test
    public void nonUtf8BytesOfASignedHeaderShouldVerify() throws Exception {
        byte[] mail = "From: joe@messiah.edu\r\nSubject: café\r\n\r\nbody\r\n".getBytes(StandardCharsets.ISO_8859_1);
        String field = dkimSigner.sign(new ByteArrayInputStream(mail));

        InputStream in = new SequenceInputStream(
                new ByteArrayInputStream((field + "\r\n").getBytes(StandardCharsets.US_ASCII)), new ByteArrayInputStream(mail));

        assertThat(verifier.verify(in)).hasSize(1);
    }

    @Test
    public void alteringNonUtf8BytesOfASignedHeaderShouldBreakTheSignature() throws Exception {
        assertTamperingNonUtf8HeaderBytesIsDetected(dkimSigner);
    }

    @Test
    public void alteringNonUtf8BytesOfASignedHeaderShouldBreakTheRelaxedSignature() throws Exception {
        DKIMSigner relaxedSigner = new DKIMSigner(SIGNATURE_TEMPLATE.replace("c=simple", "c=relaxed"), TestKeys.privateKey);
        assertTamperingNonUtf8HeaderBytesIsDetected(relaxedSigner);
    }

    private void assertTamperingNonUtf8HeaderBytesIsDetected(DKIMSigner signer) throws Exception {
        byte[] mail = "From: joe@messiah.edu\r\nSubject: café\r\n\r\nbody\r\n".getBytes(StandardCharsets.ISO_8859_1);
        byte[] tampered = "From: joe@messiah.edu\r\nSubject: cafè\r\n\r\nbody\r\n".getBytes(StandardCharsets.ISO_8859_1);
        String field = signer.sign(new ByteArrayInputStream(mail));

        InputStream in = new SequenceInputStream(
                new ByteArrayInputStream((field + "\r\n").getBytes(StandardCharsets.US_ASCII)), new ByteArrayInputStream(tampered));

        assertThatThrownBy(() -> verifier.verify(in)).isInstanceOf(PermFailException.class);
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
    @Test
    public void signatureCheckShouldConvertEachFieldAtMostOnce() throws Exception {
        StringBuilder mail = new StringBuilder();
        for (int i = 0; i < 500; i++) {
            mail.append("From: x").append(i).append("@example.com\r\n");
        }
        mail.append("\r\n");
        Message message = new Message(new ByteArrayInputStream(mail.toString().getBytes(StandardCharsets.US_ASCII)));
        AtomicInteger converted = new AtomicInteger();
        Headers counting = new Headers() {
            public List<String> getFields() {
                return message.getFields();
            }

            public List<String> getFields(String name) {
                List<String> l = message.getFields(name);
                converted.addAndGet(l.size());
                return l;
            }
        };
        SignatureRecord sign = new SignatureRecordImpl("v=1; a=rsa-sha256; d=example.com; s=s; bh=AAAA; b=AAAA; h="
                + String.join(":", Collections.nCopies(500, "from")));
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(TestKeys.privateKey);

        DKIMCommon.signatureCheck(counting, sign, sign.getHeaders(), sig);

        assertThat(converted.get()).isLessThanOrEqualTo(1000);
    }

    @Test
    public void messageShouldConvertFieldsOnce() throws Exception {
        String mail = "From: joe@example.com\r\nSubject: test\r\nfrom: jane@example.com\r\n\r\nbody\r\n";
        Message message = new Message(new ByteArrayInputStream(mail.getBytes(StandardCharsets.US_ASCII)));

        assertThat(message.getFields("FROM")).containsExactly("From: joe@example.com", "from: jane@example.com");
        assertThat(message.getFields("from")).isSameAs(message.getFields("From"));
        assertThat(message.getFields()).containsExactly("From: joe@example.com", "Subject: test", "from: jane@example.com");
        assertThat(message.getFields("missing")).isEmpty();
    }

    @Test
    public void controlCharacterAddedToARelaxedHeaderValueShouldBreakTheSignature() throws Exception {
        DKIMSigner signer = new DKIMSigner("v=1; a=rsa-sha256; c=relaxed/simple; d=messiah.edu; h=from; s=selector2;", TestKeys.privateKey);
        byte[] mail = "From: joe@messiah.edu\r\n\r\nbody\r\n".getBytes(StandardCharsets.US_ASCII);
        String field = signer.sign(new ByteArrayInputStream(mail));

        for (String tampered : Arrays.asList("From: joe@messiah.edu\u0001", "From: \u0000joe@messiah.edu", "From:\u0016 joe@messiah.edu")) {
            InputStream in = new SequenceInputStream(new ByteArrayInputStream((field + "\r\n").getBytes(StandardCharsets.US_ASCII)),
                    new ByteArrayInputStream((tampered + "\r\n\r\nbody\r\n").getBytes(StandardCharsets.US_ASCII)));

            assertThatThrownBy(() -> verifier.verify(in)).as(tampered).isInstanceOf(PermFailException.class);
        }
    }

    @Test
    public void relaxedHeaderCanonicalizationShouldIgnoreWhitespaceAroundTheValue() throws Exception {
        DKIMSigner signer = new DKIMSigner("v=1; a=rsa-sha256; c=relaxed/simple; d=messiah.edu; h=from; s=selector2;", TestKeys.privateKey);
        byte[] mail = "From: joe@messiah.edu\r\n\r\nbody\r\n".getBytes(StandardCharsets.US_ASCII);
        byte[] reformatted = "From:\t joe@messiah.edu \t\r\n\r\nbody\r\n".getBytes(StandardCharsets.US_ASCII);
        String field = signer.sign(new ByteArrayInputStream(mail));

        InputStream in = new SequenceInputStream(
                new ByteArrayInputStream((field + "\r\n").getBytes(StandardCharsets.US_ASCII)), new ByteArrayInputStream(reformatted));

        assertThat(verifier.verify(in)).hasSize(1);
    }

    @Test
    public void signatureWithATagNameEndingInBShouldVerify() throws Exception {
        DKIMSigner signer = new DKIMSigner("v=1; a=rsa-sha256; c=simple; d=messiah.edu; h=from; s=selector2; ab=x;", TestKeys.privateKey);
        byte[] mail = "From: joe@messiah.edu\r\n\r\nbody\r\n".getBytes(StandardCharsets.US_ASCII);
        String field = signer.sign(new ByteArrayInputStream(mail));

        List<SignatureRecord> verified = verifier.verify(new SequenceInputStream(
                new ByteArrayInputStream((field + "\r\n").getBytes(StandardCharsets.US_ASCII)), new ByteArrayInputStream(mail)));

        assertThat(verified).hasSize(1);
    }

    @Test
    public void simpleCanonicalizationShouldKeepTheSignatureFieldNameAsWritten() throws Exception {
        String body = "body\r\n";
        String bh = Base64.getEncoder().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(body.getBytes(StandardCharsets.US_ASCII)));
        String tags = " b=; v=1; a=rsa-sha256; c=simple/simple; d=messiah.edu; s=selector2; h=from; bh=" + bh;
        String from = "From: joe@messiah.edu";
        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initSign(TestKeys.privateKey);
        rsa.update((from + "\r\n" + "dkim-signature:" + tags).getBytes(StandardCharsets.US_ASCII));
        String b = Base64.getEncoder().encodeToString(rsa.sign());
        String mail = "dkim-signature:" + tags.replace("b=;", "b=" + b + ";") + "\r\n" + from + "\r\n\r\n" + body;

        assertThat(verifier.verify(new ByteArrayInputStream(mail.getBytes(StandardCharsets.US_ASCII)))).hasSize(1);
    }

    @Test
    public void controlCharacterBeforeASignedFieldNameShouldBreakTheSignature() throws Exception {
        DKIMSigner signer = new DKIMSigner("v=1; a=rsa-sha256; c=relaxed/simple; d=messiah.edu; h=from; s=selector2;", TestKeys.privateKey);
        byte[] mail = "From: joe@messiah.edu\r\n\r\nbody\r\n".getBytes(StandardCharsets.US_ASCII);
        byte[] tampered = "\u0000From: joe@messiah.edu\r\n\r\nbody\r\n".getBytes(StandardCharsets.US_ASCII);
        String field = signer.sign(new ByteArrayInputStream(mail));

        InputStream in = new SequenceInputStream(
                new ByteArrayInputStream((field + "\r\n").getBytes(StandardCharsets.US_ASCII)), new ByteArrayInputStream(tampered));

        assertThatThrownBy(() -> verifier.verify(in)).isInstanceOf(PermFailException.class);
    }

    @Test
    public void fieldsWhoseNameLooksLikeACommentShouldBeSigned() throws Exception {
        DKIMSigner signer = new DKIMSigner("v=1; a=rsa-sha256; c=relaxed/simple; d=messiah.edu; h=from:(((((; s=selector2;", TestKeys.privateKey);
        byte[] mail = "From: joe@messiah.edu\r\n(((((:(( signed\r\n\r\nbody\r\n".getBytes(StandardCharsets.US_ASCII);
        byte[] tampered = "From: joe@messiah.edu\r\n(((((:(( altered\r\n\r\nbody\r\n".getBytes(StandardCharsets.US_ASCII);
        String field = signer.sign(new ByteArrayInputStream(mail));

        InputStream in = new SequenceInputStream(
                new ByteArrayInputStream((field + "\r\n").getBytes(StandardCharsets.US_ASCII)), new ByteArrayInputStream(tampered));

        assertThatThrownBy(() -> verifier.verify(in)).isInstanceOf(PermFailException.class);
    }

    @Test
    public void messageShouldMatchFieldsOnTheirRawName() throws Exception {
        Message message = new Message(new ByteArrayInputStream(
                "\u0000From: a\r\nFrom : b\r\n(c) Subject: c\r\n\r\n".getBytes(StandardCharsets.US_ASCII)));

        assertThat(message.getFields("from")).containsExactly("From : b");
        assertThat(message.getFields("subject")).isEmpty();
        assertThat(message.getFields("(c) Subject")).containsExactly("(c) Subject: c");
    }

    @Test
    public void messageShouldKeepFoldedFieldsAndHeaderOnlyMessages() throws Exception {
        Message folded = new Message(new ByteArrayInputStream(
                "Subject: a\r\n\tb\r\n c\r\nFrom: d\r\n\r\nbody\r\n".getBytes(StandardCharsets.US_ASCII)));
        Message headerOnly = new Message(new ByteArrayInputStream("From: d\nTo: e".getBytes(StandardCharsets.US_ASCII)));

        assertThat(folded.getFields()).containsExactly("Subject: a\r\n\tb\r\n c", "From: d");
        assertThat(headerOnly.getFields()).containsExactly("From: d", "To: e");
    }

    @Test
    public void headerLineWithoutColonShouldMakeVerificationFail() throws Exception {
        byte[] mail = "From: joe@messiah.edu\r\n\r\nbody\r\n".getBytes(StandardCharsets.US_ASCII);
        String field = new DKIMSigner("v=1; a=rsa-sha256; c=simple; d=messiah.edu; h=from; s=selector2;", TestKeys.privateKey)
                .sign(new ByteArrayInputStream(mail));
        byte[] tampered = (field + "\r\nReply-To joe@evil.example\r\nFrom: joe@messiah.edu\r\n\r\nbody\r\n")
                .getBytes(StandardCharsets.US_ASCII);

        assertThatThrownBy(() -> verifier.verify(new ByteArrayInputStream(tampered)))
                .isInstanceOf(PermFailException.class)
                .hasMessageContaining("Mime parsing exception");
    }

    @Test
    public void malformedHeaderBlocksShouldBeRejected() {
        for (String header : Arrays.asList("j\t\r\n", "From: a\r\nD(*\r\n", " x: y\r\nFrom: a\r\n")) {
            assertThatThrownBy(() -> new Message(new ByteArrayInputStream((header + "\r\nbody\r\n").getBytes(StandardCharsets.US_ASCII))))
                    .as(header)
                    .isInstanceOf(MimeException.class);
        }
    }

    @Test
    public void duplicateSignatureFieldsShouldEachHaveAResult() throws Exception {
        String field = "DKIM-Signature: v=1; a=rsa-sha256; d=messiah.edu; s=selector2; h=from; bh=AAAA; b=AAAA\r\n";
        String mail = field + field + "From: joe@messiah.edu\r\n\r\nbody\r\n";

        assertThatThrownBy(() -> verifier.verify(new ByteArrayInputStream(mail.getBytes(StandardCharsets.US_ASCII))))
                .isInstanceOf(CompositeFailException.class);

        assertThat(verifier.getResults()).hasSize(2);
    }

    @Test
    public void resultsShouldFollowTheFieldOrder() throws Exception {
        byte[] mail = "From: joe@messiah.edu\r\n\r\nbody\r\n".getBytes(StandardCharsets.US_ASCII);
        String valid = dkimSigner.sign(new ByteArrayInputStream(mail));
        String invalid = "DKIM-Signature: v=1; a=rsa-sha256; d=messiah.edu; s=selector3; h=from; bh=AAAA; b=AAAA";
        String signed = invalid + "\r\n" + valid + "\r\n" + invalid + "\r\n";

        verifier.verify(new SequenceInputStream(
                new ByteArrayInputStream(signed.getBytes(StandardCharsets.US_ASCII)), new ByteArrayInputStream(mail)));

        assertThat(verifier.getResults()).extracting(Result::isSuccess).containsExactly(false, true, false);
    }

    @Test
    public void signatureListingDkimSignatureInHShouldVerify() throws Exception {
        DKIMSigner signer = new DKIMSigner("v=1; a=rsa-sha256; c=simple; d=messiah.edu; h=from:DKIM-Signature; s=selector2;", TestKeys.privateKey);
        byte[] mail = "From: joe@messiah.edu\r\n\r\nbody\r\n".getBytes(StandardCharsets.US_ASCII);
        String field = signer.sign(new ByteArrayInputStream(mail));

        List<SignatureRecord> verified = verifier.verify(new SequenceInputStream(
                new ByteArrayInputStream((field + "\r\n").getBytes(StandardCharsets.US_ASCII)), new ByteArrayInputStream(mail)));

        assertThat(verified).hasSize(1);
    }

    @Test
    public void signatureOverAnEarlierSignatureShouldVerify() throws Exception {
        byte[] mail = "From: joe@messiah.edu\r\n\r\nbody\r\n".getBytes(StandardCharsets.US_ASCII);
        String first = dkimSigner.sign(new ByteArrayInputStream(mail));
        byte[] signedOnce = (first + "\r\n" + new String(mail, StandardCharsets.US_ASCII)).getBytes(StandardCharsets.US_ASCII);
        String second = new DKIMSigner("v=1; a=rsa-sha256; c=relaxed; d=messiah.edu; h=from:DKIM-Signature:DKIM-Signature; s=selector3;", TestKeys.privateKey_2)
                .sign(new ByteArrayInputStream(signedOnce));
        byte[] tampered = (second + "\r\n" + first.replace("h=", "h=to:") + "\r\n" + new String(mail, StandardCharsets.US_ASCII))
                .getBytes(StandardCharsets.US_ASCII);

        List<SignatureRecord> verified = verifier.verify(new SequenceInputStream(
                new ByteArrayInputStream((second + "\r\n").getBytes(StandardCharsets.US_ASCII)), new ByteArrayInputStream(signedOnce)));
        assertThat(verified).hasSize(2);

        verifier.resetResults();
        assertThatThrownBy(() -> verifier.verify(new ByteArrayInputStream(tampered)))
                .isInstanceOf(CompositeFailException.class);
    }

    @Test
    public void headerCharsAboveU00FFShouldNotBeHashedAsQuestionMarks() throws Exception {
        String template = "v=1; d=messiah.edu; s=selector2; a=rsa-sha256; c=simple/simple; h=from;";
        DKIMSigner signer = new DKIMSigner(template, TestKeys.privateKey);
        BodyHasher bodyHasher = signer.newBodyHasher(signer.newSignatureRecordTemplate(template));
        bodyHasher.getOutputStream().close();
        // getBytes(ISO_8859_1) used to turn any char above U+00FF into this '?'
        String signature = signer.sign(headers("From: joe@messiah.edu?"), bodyHasher);

        assertThatThrownBy(() -> signer.sign(headers("From: " + (char) 0xA9C3), bodyHasher))
                .isInstanceOf(PermFailException.class);
        assertThatThrownBy(() -> verifier.verify(headers(signature, "From: joe@messiah.edu" + (char) 0x100),
                new ByteArrayInputStream(new byte[0])))
                .isInstanceOf(PermFailException.class);
    }

    private static Headers headers(String... fields) {
        List<String> all = Arrays.asList(fields);
        return new Headers() {
            public List<String> getFields() {
                return all;
            }

            public List<String> getFields(String name) {
                return all.stream()
                        .filter(f -> f.substring(0, f.indexOf(':')).equalsIgnoreCase(name))
                        .collect(Collectors.toList());
            }
        };
    }

    private static final String SINGLE_FROM_MESSAGE = "From: alice@messiah.edu\r\nSubject: hello\r\n\r\nbody\r\n";

    private String replayWithExtraFrom(String template) throws Exception {
        DKIMSigner signer = new DKIMSigner(template, TestKeys.privateKey);
        String signature = signer.sign(new ByteArrayInputStream(SINGLE_FROM_MESSAGE.getBytes(StandardCharsets.US_ASCII)));
        return "From: someone-else@example.net\r\n" + signature + "\r\n" + SINGLE_FROM_MESSAGE;
    }

    private DKIMVerifier verifierWith(UnsignedDuplicateFieldPolicy policy) {
        return new DKIMVerifier(new VerifierOptions.Builder()
                .withPublicKeyRecordRetriever(keyRecordRetriever)
                .withUnsignedDuplicateFieldPolicy(policy)
                .build());
    }

    @Test
    public void unsignedExtraFromFieldShouldNotPassSilently() throws Exception {
        String replayed = replayWithExtraFrom("v=1; a=rsa-sha256; c=simple; d=messiah.edu; h=from:subject; q=dns/txt; s=selector2;");

        DKIMVerifier strictVerifier = verifierWith(UnsignedDuplicateFieldPolicy.REJECT);

        assertThatThrownBy(() -> strictVerifier.verify(new ByteArrayInputStream(replayed.getBytes(StandardCharsets.US_ASCII))))
                .isInstanceOf(FailException.class)
                .hasMessageContaining("2 from fields");
        assertThat(strictVerifier.hasAnyValidSignature()).isFalse();
        assertThat(strictVerifier.getResults()).singleElement()
                .satisfies(r -> assertThat(r.getErrorMessage()).contains("2 from fields"));
    }

    @Test
    public void unsignedExtraFromFieldShouldBeRejectedByDefault() throws Exception {
        String replayed = replayWithExtraFrom("v=1; a=rsa-sha256; c=simple; d=messiah.edu; h=from:subject; q=dns/txt; s=selector2;");

        assertThatThrownBy(() -> verifier.verify(new ByteArrayInputStream(replayed.getBytes(StandardCharsets.US_ASCII))))
                .isInstanceOf(FailException.class);
        assertThat(verifier.hasAnyValidSignature()).isFalse();
    }

    @Test
    public void unsignedExtraFromFieldShouldBeFlaggedWhenConfigured() throws Exception {
        String replayed = replayWithExtraFrom("v=1; a=rsa-sha256; c=simple; d=messiah.edu; h=from:subject; q=dns/txt; s=selector2;");

        DKIMVerifier flaggingVerifier = verifierWith(UnsignedDuplicateFieldPolicy.FLAG);

        assertThat(flaggingVerifier.verify(new ByteArrayInputStream(replayed.getBytes(StandardCharsets.US_ASCII)))).hasSize(1);
        assertThat(flaggingVerifier.getResults()).singleElement().satisfies(r -> {
            assertThat(r.getResultType()).isEqualTo(Result.Type.PASS);
            assertThat(r.getWarning()).contains("2 from fields");
            assertThat(r.getHeaderTextWithReason()).contains("reason=\"valid signature, but the message has 2 from fields");
        });
    }

    @Test
    public void unsignedExtraFromFieldShouldPassWhenAccepted() throws Exception {
        String replayed = replayWithExtraFrom("v=1; a=rsa-sha256; c=simple; d=messiah.edu; h=from:subject; q=dns/txt; s=selector2;");

        DKIMVerifier lenientVerifier = verifierWith(UnsignedDuplicateFieldPolicy.ACCEPT);

        assertThat(lenientVerifier.verify(new ByteArrayInputStream(replayed.getBytes(StandardCharsets.US_ASCII)))).hasSize(1);
        assertThat(lenientVerifier.getResults()).singleElement()
                .satisfies(r -> assertThat(r.getWarning()).isNull());
    }

    @Test
    public void oversignedFromShouldStillFailWhenAFromFieldIsAdded() throws Exception {
        String replayed = replayWithExtraFrom("v=1; a=rsa-sha256; c=simple; d=messiah.edu; h=from:from:subject; q=dns/txt; s=selector2;");

        DKIMVerifier lenientVerifier = verifierWith(UnsignedDuplicateFieldPolicy.ACCEPT);

        assertThatThrownBy(() -> lenientVerifier.verify(new ByteArrayInputStream(replayed.getBytes(StandardCharsets.US_ASCII))))
                .isInstanceOf(PermFailException.class)
                .hasMessageContaining("Header signature does not verify");
    }

    @Test
    public void singleFromFieldShouldPassWithoutWarning() throws Exception {
        DKIMSigner signer = new DKIMSigner("v=1; a=rsa-sha256; c=simple; d=messiah.edu; h=from:subject; q=dns/txt; s=selector2;", TestKeys.privateKey);
        String signature = signer.sign(new ByteArrayInputStream(SINGLE_FROM_MESSAGE.getBytes(StandardCharsets.US_ASCII)));
        String signed = signature + "\r\n" + SINGLE_FROM_MESSAGE;

        DKIMVerifier flaggingVerifier = verifierWith(UnsignedDuplicateFieldPolicy.FLAG);

        assertThat(flaggingVerifier.verify(new ByteArrayInputStream(signed.getBytes(StandardCharsets.US_ASCII)))).hasSize(1);
        assertThat(flaggingVerifier.getResults()).singleElement()
                .satisfies(r -> assertThat(r.getWarning()).isNull());
    }

    @Test
    public void unsignedExtraReplyToFieldShouldNotPassSilently() throws Exception {
        DKIMSigner signer = new DKIMSigner(
                "v=1; a=rsa-sha256; c=simple; d=messiah.edu; h=from:reply-to:subject; q=dns/txt; s=selector2;",
                TestKeys.privateKey);
        String message = "From: alice@messiah.edu\r\nReply-To: alice@messiah.edu\r\nSubject: hello\r\n\r\nbody\r\n";
        String signature = signer.sign(new ByteArrayInputStream(message.getBytes(StandardCharsets.US_ASCII)));
        String replayed = "Reply-To: someone-else@example.net\r\n" + signature + "\r\n" + message;

        assertThatThrownBy(() -> verifier.verify(new ByteArrayInputStream(replayed.getBytes(StandardCharsets.US_ASCII))))
                .isInstanceOf(FailException.class)
                .hasMessageContaining("2 reply-to fields");
        assertThat(verifier.hasAnyValidSignature()).isFalse();
    }

    @Test
    public void duplicateFieldNotListedInHShouldNotBeChecked() throws Exception {
        String message = "To: bob@messiah.edu\r\n" + SINGLE_FROM_MESSAGE;
        DKIMSigner signer = new DKIMSigner("v=1; a=rsa-sha256; c=simple; d=messiah.edu; h=from:subject; q=dns/txt; s=selector2;", TestKeys.privateKey);
        String signature = signer.sign(new ByteArrayInputStream(message.getBytes(StandardCharsets.US_ASCII)));
        String withExtraTo = "To: carol@example.net\r\n" + signature + "\r\n" + message;

        assertThat(verifier.verify(new ByteArrayInputStream(withExtraTo.getBytes(StandardCharsets.US_ASCII)))).hasSize(1);
    }

    @Test
    public void configuredSingleInstanceFieldsShouldBeChecked() throws Exception {
        String replayed = replayWithExtraFrom("v=1; a=rsa-sha256; c=simple; d=messiah.edu; h=from:subject; q=dns/txt; s=selector2;");

        DKIMVerifier subjectOnlyVerifier = new DKIMVerifier(new VerifierOptions.Builder()
                .withPublicKeyRecordRetriever(keyRecordRetriever)
                .withSingleInstanceFields(Collections.singletonList("Subject"))
                .build());

        assertThat(subjectOnlyVerifier.verify(new ByteArrayInputStream(replayed.getBytes(StandardCharsets.US_ASCII)))).hasSize(1);
    }

    private static final String KEY = Base64.getEncoder().encodeToString(TestKeys.publicKey.getEncoded());

    private Result.Type resultTypeWithKeyRecord(String signatureTemplate, String keyRecord, boolean alterBody) throws Exception {
        MockPublicKeyRecordRetriever retriever = keyRecord == null
                ? new MockPublicKeyRecordRetriever()
                : new MockPublicKeyRecordRetriever(Record.of("selector2", "messiah.edu", keyRecord));
        DKIMVerifier verifier = new DKIMVerifier(new VerifierOptions.Builder().withPublicKeyRecordRetriever(retriever).build());

        String message = "From: joe@messiah.edu\r\nSubject: test\r\n\r\nbody\r\n";
        String signature = new DKIMSigner(signatureTemplate, TestKeys.privateKey)
                .sign(new ByteArrayInputStream(message.getBytes(StandardCharsets.US_ASCII)));
        String signed = signature + "\r\n" + (alterBody ? message.replace("body", "b0dy") : message);

        assertThatThrownBy(() -> verifier.verify(new ByteArrayInputStream(signed.getBytes(StandardCharsets.US_ASCII))))
                .isInstanceOf(PermFailException.class);
        assertThat(verifier.getResults()).hasSize(1);
        return verifier.getResults().get(0).getResultType();
    }

    @Test
    public void unusableKeysShouldBeReportedAsPermerror() throws Exception {
        String[] keyRecords = {
                null,
                "v=DKIM1; k=rsa; p=",
                "v=DKIM2; k=rsa; p=" + KEY,
                "v=DKIM1; k=rsa; p=AAAA",
                "v=DKIM1; k=ec; p=" + KEY,
                "v=DKIM1; k=rsa; h=sha1; p=" + KEY};
        for (String keyRecord : keyRecords) {
            assertThat(resultTypeWithKeyRecord(SIGNATURE_TEMPLATE, keyRecord, false))
                    .as("key record %s", keyRecord)
                    .isEqualTo(Result.Type.PERMERROR);
        }
    }

    @Test
    public void keyRestrictedToTheSdidShouldBeReportedAsPermerrorForASubdomainIdentity() throws Exception {
        String template = "v=1; a=rsa-sha256; c=simple; d=messiah.edu; i=@sub.messiah.edu; h=from:subject; q=dns/txt; s=selector2;";

        assertThat(resultTypeWithKeyRecord(template, "v=DKIM1; k=rsa; t=s; p=" + KEY, false))
                .isEqualTo(Result.Type.PERMERROR);
    }

    @Test
    public void bodyChangedAfterSigningShouldStillBeReportedAsFail() throws Exception {
        assertThat(resultTypeWithKeyRecord(SIGNATURE_TEMPLATE, "v=DKIM1; k=rsa; p=" + KEY, true))
                .isEqualTo(Result.Type.FAIL);
    }

    @Test
    public void headerChangedAfterSigningShouldStillBeReportedAsFail() throws Exception {
        String message = "From: joe@messiah.edu\r\nSubject: test\r\n\r\nbody\r\n";
        String signature = dkimSigner.sign(new ByteArrayInputStream(message.getBytes(StandardCharsets.US_ASCII)));
        String altered = signature + "\r\n" + message.replace("Subject: test", "Subject: tost");

        assertThatThrownBy(() -> verifier.verify(new ByteArrayInputStream(altered.getBytes(StandardCharsets.US_ASCII))))
                .isInstanceOf(PermFailException.class);
        assertThat(verifier.getResults()).extracting(Result::getResultType).containsExactly(Result.Type.FAIL);
    }

    @Test
    public void signerShouldRejectAlgorithmsOutsideRfc6376() {
        assertThatThrownBy(() -> new DKIMSigner("v=1; a=rsa-md5; c=simple; d=messiah.edu; h=from:subject; q=dns/txt; s=selector2;", TestKeys.privateKey)
                .sign(new ByteArrayInputStream(SINGLE_FROM_MESSAGE.getBytes(StandardCharsets.US_ASCII))))
                .hasMessageContaining("algorithm");
    }

    @Test
    public void verifierShouldReportAlgorithmsOutsideRfc6376AsPermerror() {
        String mail = "DKIM-Signature: v=1; a=rsa-md5; c=simple; d=messiah.edu; s=selector2; h=from:subject; bh=AAAA; b=AAAA\r\n"
                + SINGLE_FROM_MESSAGE;

        assertThatThrownBy(() -> verifier.verify(new ByteArrayInputStream(mail.getBytes(StandardCharsets.US_ASCII))))
                .isInstanceOf(PermFailException.class)
                .hasMessageContaining("algorithm");
        assertThat(verifier.getResults()).extracting(Result::getResultType).containsExactly(Result.Type.PERMERROR);
    }

    @Test
    public void signedFieldLinesShouldBeFoldedAndStillVerify() throws Exception {
        StringBuilder h = new StringBuilder("from");
        for (int i = 0; i < 100; i++) {
            h.append(":from");
        }
        String message = "From: joe@messiah.edu\r\nSubject: hi\r\n\r\nbody\r\n";
        for (String c : new String[] {"simple/simple", "relaxed/relaxed"}) {
            String template = "v=1; a=rsa-sha256; c=" + c + "; d=messiah.edu; s=selector2; q=dns/txt; h=" + h
                    + "; z=From:joe@messiah.edu;";
            String field = new DKIMSigner(template, TestKeys.privateKey)
                    .sign(new ByteArrayInputStream(message.getBytes(StandardCharsets.US_ASCII)));

            for (String line : field.split("\r\n")) {
                assertThat(line.length()).as("line [%s] with c=%s", line, c).isLessThanOrEqualTo(78);
            }
            verifier.resetResults();
            String signed = field + "\r\n" + message;
            assertThat(verifier.verify(new ByteArrayInputStream(signed.getBytes(StandardCharsets.US_ASCII))))
                    .as("c=%s", c)
                    .hasSize(1);
        }
    }

}
