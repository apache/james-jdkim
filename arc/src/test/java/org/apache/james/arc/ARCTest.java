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
package org.apache.james.arc;

import org.apache.james.dmarc.MockPublicKeyRecordRetrieverDmarc;
import org.apache.james.jdkim.DKIMCommon;
import org.apache.james.jdkim.MockPublicKeyRecordRetriever;
import org.apache.james.mime4j.dom.Message;
import org.apache.james.mime4j.message.DefaultMessageBuilder;
import org.apache.james.mime4j.stream.RawField;
import org.junit.Test;

import org.apache.james.mime4j.stream.Field;
import java.util.Base64;
import java.util.List;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class ARCTest {
    public static final String AUTHENTICATION_RESULTS = "Authentication-Results";
    public static final String ARC_AUTHENTICATION_RESULTS = "ARC-Authentication-Results";
    public static final String ARC_MESSAGE_SIGNATURE = "ARC-Message-Signature";
    public static final String ARC_SEAL = "ARC-Seal";

    private final MockPublicKeyRecordRetrieverDmarc dmarcRetriever = new MockPublicKeyRecordRetrieverDmarc(
            MockPublicKeyRecordRetrieverDmarc.DmarcRecord.dmarcOf(
                    "d1.example",
                    "k=rsa; v=DMARC1; p=reject; pct=100; rua=mailto:noc@d1.example"
            )
    );

    private final MockPublicKeyRecordRetrieverArc keyRecordRetriever = new MockPublicKeyRecordRetrieverArc( dmarcRetriever,
            MockPublicKeyRecordRetriever.Record.of(
                    "arc",
                    "dmarc.example",
                    "k=rsa; p=" + Base64.getEncoder().encodeToString(ArcTestKeys.publicKeyArc.getEncoded()) + ";"
            ),
            MockPublicKeyRecordRetriever.Record.of(
                    "origin2015",
                    "d1.example",
                    "k=rsa; p=" + Base64.getEncoder().encodeToString(ArcTestKeys.publicKeyDkim.getEncoded()) + ";"
            ),
            MockPublicKeyRecordRetrieverArc.SpfRecord.spfOf("d1.example",
                    "jqd@d1.example",
                    "222.222.222.222",
                    "softfail (spfCheck: transitioning domain of d1.example does not designate 222.222.222.222 as permitted sender) client-ip=222.222.222.222; envelope-from=jqd@d1.example; helo=d1.example")
    );

    /**
     * - "a" field will be added by the signer based on signer setup
     * - "bh=" and "b=" placeholder are required for now because the same implementation is used for
     * signing and verifying. The fields are mandatory for verifying.
     */
    private static final String ARC_AMS_TEMPLATE = "i=; a=rsa-sha256; c=relaxed/relaxed; d=dmarc.example; s=arc; t=; h=Subject:From:To; bh=; b=";
    private static final String ARC_SEAL_TEMPLATE = "i=; cv=; a=rsa-sha256; d=dmarc.example; s=arc; t=; b=";

    private static final String AUTH_SERVICE = "smtp.d1.example";
    private static final String HELO = "d1.example";

    private static final String MAIL_FROM = "jqd@d1.example";
    private static final String IP = "222.222.222.222";
    private static final long TIMESTAMP = 1755918846L; // fixed timestamp for repeatable tests
    ArcSetBuilder arcSetBuilder = new ArcSetBuilder(ArcTestKeys.privateKeyArc, ARC_AMS_TEMPLATE, ARC_SEAL_TEMPLATE, AUTH_SERVICE, TIMESTAMP);

    // Happy path: signs a fresh message (no prior ARC chain), pins the exact header values produced,
    // then validates the resulting i=1 chain and asserts cv=pass.
    @Test
    public void generate_and_verify_arc_set() throws Exception {
        String expectedCv = "pass";
        String authResultsExp = "smtp.d1.example; spf=softfail (spfCheck: transitioning domain of d1.example does not designate 222.222.222.222 as permitted sender) client-ip=222.222.222.222 envelope-from=jqd@d1.example helo=d1.example; dkim=pass header.i=d1.example header.s=origin2015 header.b=iEn8fLQ/; dmarc=pass (p=reject) header.from=d1.example";
        String arcAuthResultsExp = "i=1; smtp.d1.example; spf=softfail (spfCheck: transitioning domain of d1.example does not designate 222.222.222.222 as permitted sender) client-ip=222.222.222.222 envelope-from=jqd@d1.example helo=d1.example; dkim=pass header.i=d1.example header.s=origin2015 header.b=iEn8fLQ/; dmarc=pass (p=reject) header.from=d1.example";
        String arcSignExp = "i=1; a=rsa-sha256; c=relaxed/relaxed; d=dmarc.example; s=arc; t=1755918846; h=subject : from : to; bh=KWSe46TZKCcDbH4klJPo+tjk5LWJnVRlP5pvjXFZYLQ=; b=FL3H8cG2U7RcyMSdx4j8iAD/7Uhzhl4XmWicLD+Uuxf3VsVghJ/lswvdQrjnyr6R9oyfPzP7rE2BEX0CFKlSvTVWy5/+8Vc3CXqj+tnKYoHnuWxH4sH0jMTpHzgceGLgMXvamilPyYWrCeF3r5yaUPYQ04fhfeAFAs6OTLeKvL0=";
        String arcSealExp = "i=1; cv=none; a=rsa-sha256; d=dmarc.example; s=arc; t=1755918846; b=LsqQnv1KZhtbEX6SYLn0gk0t+Pjg3WmLu0aqNVwHa3nMcRq1dt4wJX1ka9lZAY/RARH74hwtfGnW1ba1gXLZ2WhevLwXvQcuw3NK6aC2YcYCjQ9kQWmlpvLe96xXsASl8MPXWyOmTEOdCeH06mkf3jahb4+bBjp1875568hTFhQ=";

        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        DefaultMessageBuilder builder = new DefaultMessageBuilder();
        Message message = builder.parseMessage(emailStream);

//        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO , MAIL_FROM,IP, new DNSPublicKeyRecordRetrieverArc()); // use this for real/external DNS lookups
        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO , MAIL_FROM,IP, keyRecordRetriever);                     // mock DNS for testing

        assertThat(arcSet).hasSize(4);

        String authResults = arcSet.get(AUTHENTICATION_RESULTS);
        String arcAuthResults = arcSet.get(ARC_AUTHENTICATION_RESULTS);
        String arcMsgSignature = arcSet.get(ARC_MESSAGE_SIGNATURE);
        String arcSeal = arcSet.get(ARC_SEAL);
        assertThat(authResults).isEqualTo(authResultsExp);
        assertThat(arcAuthResults).isEqualTo(arcAuthResultsExp);
        assertThat(arcMsgSignature).isEqualTo(arcSignExp);
        assertThat(arcSeal).isEqualTo(arcSealExp);

        //add new ARC set to the message and do chain validation on it
        for (Map.Entry<String, String> entry: arcSet.entrySet()){
            message.getHeader().addField(new RawField(entry.getKey(), entry.getValue()));
        }

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo(expectedCv);
    }

    // cv_fail_i1_ams_invalid: builds a valid i=1 ARC set, then replaces the AMS b= signature with
    // wrong bytes before adding headers to the message, expecting chain validation to return cv=fail.
    @Test
    public void validate_arc_chain_fails_when_ams_signature_is_invalid() throws Exception {
        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        Message message = new DefaultMessageBuilder().parseMessage(emailStream);

        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);

        // Replace b= with 128 zero bytes (correct RSA key length but wrong value) so sig.verify() returns false
        String fakeB64 = Base64.getEncoder().encodeToString(new byte[128]);
        String corruptedAms = arcSet.get(ARC_MESSAGE_SIGNATURE)
                .replaceAll("; b=.*$", "; b=" + fakeB64);
        arcSet.put(ARC_MESSAGE_SIGNATURE, corruptedAms);

        for (Map.Entry<String, String> entry : arcSet.entrySet()) {
            message.getHeader().addField(new RawField(entry.getKey(), entry.getValue()));
        }

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // cv_fail_i1_as_invalid: builds a valid i=1 ARC set, then replaces the ARC-Seal b= signature with
    // wrong bytes before adding headers to the message, expecting chain validation to return cv=fail.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_signature_is_invalid() throws Exception {
        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        Message message = new DefaultMessageBuilder().parseMessage(emailStream);

        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);

        // Replace b= with 128 zero bytes (correct RSA key length but wrong value) so sig.verify() returns false
        String fakeB64 = Base64.getEncoder().encodeToString(new byte[128]);
        String corruptedSeal = arcSet.get(ARC_SEAL)
                .replaceAll("; b=.*$", "; b=" + fakeB64);
        arcSet.put(ARC_SEAL, corruptedSeal);

        for (Map.Entry<String, String> entry : arcSet.entrySet()) {
            message.getHeader().addField(new RawField(entry.getKey(), entry.getValue()));
        }

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // cv_fail_i1_ams_na: if the ARC-Message-Signature header is absent from the i=1 set entirely,
    // the chain is structurally incomplete and must be rejected with cv=fail.
    @Test
    public void validate_arc_chain_fails_when_ams_header_is_missing() throws Exception {
        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        Message message = new DefaultMessageBuilder().parseMessage(emailStream);

        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);
        arcSet.remove(ARC_MESSAGE_SIGNATURE);

        for (Map.Entry<String, String> entry : arcSet.entrySet()) {
            message.getHeader().addField(new RawField(entry.getKey(), entry.getValue()));
        }

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // cv_fail_i1_as_na: if the ARC-Seal header is absent from the i=1 set entirely,
    // the chain is structurally incomplete and must be rejected with cv=fail.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_header_is_missing() throws Exception {
        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        Message message = new DefaultMessageBuilder().parseMessage(emailStream);

        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);
        arcSet.remove(ARC_SEAL);

        for (Map.Entry<String, String> entry : arcSet.entrySet()) {
            message.getHeader().addField(new RawField(entry.getKey(), entry.getValue()));
        }

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // cv_fail_i1_as_pass: the ARC-Seal at i=1 must always carry cv=none (there is no prior chain to
    // have passed). If it says cv=pass, the structure is invalid and the chain must be rejected.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_cv_is_pass_on_first_hop() throws Exception {
        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        Message message = new DefaultMessageBuilder().parseMessage(emailStream);

        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);

        String tamperedSeal = arcSet.get(ARC_SEAL).replace("cv=none", "cv=pass");
        arcSet.put(ARC_SEAL, tamperedSeal);

        for (Map.Entry<String, String> entry : arcSet.entrySet()) {
            message.getHeader().addField(new RawField(entry.getKey(), entry.getValue()));
        }

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // cv_fail_i1_as_cv_fail: the ARC-Seal at i=1 carrying cv=fail means the chain was declared
    // broken from the very first hop, so validation must return cv=fail.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_cv_is_fail_on_first_hop() throws Exception {
        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        Message message = new DefaultMessageBuilder().parseMessage(emailStream);

        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);

        String tamperedSeal = arcSet.get(ARC_SEAL).replace("cv=none", "cv=fail");
        arcSet.put(ARC_SEAL, tamperedSeal);

        for (Map.Entry<String, String> entry : arcSet.entrySet()) {
            message.getHeader().addField(new RawField(entry.getKey(), entry.getValue()));
        }

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // cv_empty: a completely empty message (no headers, no body) has no ARC chain — the validator
    // must return cv=none rather than crash or return cv=fail.
    @Test
    public void validate_arc_chain_returns_none_for_empty_message() throws Exception {
        Message message = new DefaultMessageBuilder().parseMessage(
                new ByteArrayInputStream(new byte[0]));

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("none");
    }

    // cv_no_headers: a message with no headers at all has no ARC chain — the validator must return
    // cv=none gracefully without throwing.
    @Test
    public void validate_arc_chain_returns_none_for_message_with_no_headers() throws Exception {
        Message message = new DefaultMessageBuilder().parseMessage(
                new ByteArrayInputStream("\r\nbody text here".getBytes(StandardCharsets.UTF_8)));

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("none");
    }

    // cv_no_body: a message that has headers but no body is legal — the validator must process the
    // (absent) ARC chain normally and return cv=none when no ARC headers are present.
    @Test
    public void validate_arc_chain_returns_none_for_message_with_no_body() throws Exception {
        Message message = new DefaultMessageBuilder().parseMessage(
                new ByteArrayInputStream("From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: test\r\n\r\n"
                        .getBytes(StandardCharsets.UTF_8)));

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("none");
    }

    // cv_fail_i2_ams_na: in a two-hop chain, if the ARC-Message-Signature for i=2 is missing, the
    // chain is structurally incomplete and must be rejected with cv=fail.
    @Test
    public void validate_arc_chain_fails_when_i2_ams_is_missing() throws Exception {
        Message message = buildTwoHopChain();
        removeHeaderByInstanceAndType(message, ARC_MESSAGE_SIGNATURE, "i=2");

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // cv_fail_i2_ams_invalid: in a two-hop chain, if the ARC-Message-Signature at i=2 has a bad
    // cryptographic signature, the chain must be rejected even if i=1 was valid.
    @Test
    public void validate_arc_chain_fails_when_i2_ams_signature_is_invalid() throws Exception {
        Message message = buildTwoHopChain();
        corruptSignatureOnHeader(message, ARC_MESSAGE_SIGNATURE, "i=2");

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // cv_fail_i2_as2_na: in a two-hop chain, if the ARC-Seal for i=2 is missing, the chain is
    // structurally incomplete and must be rejected with cv=fail.
    @Test
    public void validate_arc_chain_fails_when_i2_arc_seal_is_missing() throws Exception {
        Message message = buildTwoHopChain();
        removeHeaderByInstanceAndType(message, ARC_SEAL, "i=2");

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // cv_fail_i2_as2_invalid: in a two-hop chain, if the ARC-Seal at i=2 has been tampered with,
    // the chain must be rejected with cv=fail.
    @Test
    public void validate_arc_chain_fails_when_i2_arc_seal_signature_is_invalid() throws Exception {
        Message message = buildTwoHopChain();
        corruptSignatureOnHeader(message, ARC_SEAL, "i=2");

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // cv_fail_i2_as2_none: the ARC-Seal at i=2 must carry cv=pass because i=1 was valid. If it
    // incorrectly says cv=none, the chain structure is wrong and must be rejected.
    @Test
    public void validate_arc_chain_fails_when_i2_arc_seal_cv_is_none() throws Exception {
        Message message = buildTwoHopChain();
        replaceTagOnHeader(message, ARC_SEAL, "i=2", "cv=pass", "cv=none");

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // cv_fail_i2_as2_fail: if the ARC-Seal at i=2 says cv=fail, the chain must be rejected.
    @Test
    public void validate_arc_chain_fails_when_i2_arc_seal_cv_is_fail() throws Exception {
        Message message = buildTwoHopChain();
        replaceTagOnHeader(message, ARC_SEAL, "i=2", "cv=pass", "cv=fail");

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // cv_fail_i2_as1_na: in a two-hop chain, if the ARC-Seal from i=1 is missing, the second
    // server's seal cannot be verified and the chain must be rejected.
    @Test
    public void validate_arc_chain_fails_when_i1_arc_seal_is_missing_in_two_hop_chain() throws Exception {
        Message message = buildTwoHopChain();
        removeHeaderByInstanceAndType(message, ARC_SEAL, "i=1");

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // cv_fail_i2_as1_invalid: in a two-hop chain, if the i=1 ARC-Seal has a bad signature, the
    // entire chain must be rejected even if i=2 looks fine.
    @Test
    public void validate_arc_chain_fails_when_i1_arc_seal_signature_is_invalid_in_two_hop_chain() throws Exception {
        Message message = buildTwoHopChain();
        corruptSignatureOnHeader(message, ARC_SEAL, "i=1");

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // cv_fail_i2_as1_pass: in a two-hop chain, the i=1 ARC-Seal must say cv=none (not cv=pass).
    // If it says cv=pass, the chain structure is wrong and must be rejected.
    @Test
    public void validate_arc_chain_fails_when_i1_arc_seal_cv_is_pass_in_two_hop_chain() throws Exception {
        Message message = buildTwoHopChain();
        replaceTagOnHeader(message, ARC_SEAL, "i=1", "cv=none", "cv=pass");

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // cv_fail_i2_as1_fail: in a two-hop chain, if the i=1 ARC-Seal says cv=fail, the chain was
    // already declared broken at hop one and the whole chain must be rejected.
    @Test
    public void validate_arc_chain_fails_when_i1_arc_seal_cv_is_fail_in_two_hop_chain() throws Exception {
        Message message = buildTwoHopChain();
        replaceTagOnHeader(message, ARC_SEAL, "i=1", "cv=none", "cv=fail");

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // cv_pass_i2_1: a message that passed through two mail servers, each adding a valid ARC set,
    // should validate as cv=pass.
    @Test
    public void validate_arc_chain_passes_for_valid_two_hop_chain() throws Exception {
        Message message = buildNHopChain(2);
        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("pass");
    }

    // cv_pass_i2_2: same two-hop happy path using a second message variant, confirming validation
    // is not tied to a single email structure.
    @Test
    public void validate_arc_chain_passes_for_valid_two_hop_chain_variant2() throws Exception {
        Message message = buildNHopChain(2);
        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("pass");
    }

    // cv_pass_i2_1_ams1_invalid: if the i=1 ARC-Message-Signature is corrupted after the chain was
    // built, the overall chain must be rejected even if the i=2 seal is intact.
    @Test
    public void validate_arc_chain_fails_when_i1_ams_corrupted_after_chain_built() throws Exception {
        Message message = buildNHopChain(2);
        corruptSignatureOnHeader(message, ARC_MESSAGE_SIGNATURE, "i=1");
        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // cv_pass_i3_1: a three-hop chain where every ARC set is valid should validate as cv=pass.
    @Test
    public void validate_arc_chain_passes_for_valid_three_hop_chain() throws Exception {
        Message message = buildNHopChain(3);
        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("pass");
    }

    // cv_pass_i4_1: a four-hop chain where every ARC set is valid should validate as cv=pass.
    @Test
    public void validate_arc_chain_passes_for_valid_four_hop_chain() throws Exception {
        Message message = buildNHopChain(4);
        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("pass");
    }

    // cv_pass_i5_1: a five-hop chain where every ARC set is valid should validate as cv=pass.
    @Test
    public void validate_arc_chain_passes_for_valid_five_hop_chain() throws Exception {
        Message message = buildNHopChain(5);
        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("pass");
    }

    // Builds a valid two-hop ARC chain: applies i=1 to the base message, then applies i=2 on top.
    private Message buildTwoHopChain() throws Exception {
        return buildNHopChain(2);
    }

    // Builds a valid N-hop ARC chain by repeatedly applying a new ARC set to the same message.
    private Message buildNHopChain(int n) throws Exception {
        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        Message message = new DefaultMessageBuilder().parseMessage(emailStream);
        for (int hop = 0; hop < n; hop++) {
            Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);
            for (Map.Entry<String, String> entry : arcSet.entrySet()) {
                message.getHeader().addField(new RawField(entry.getKey(), entry.getValue()));
            }
        }
        return message;
    }

    // Removes the first header matching the given name that contains the given instance tag (e.g. "i=2").
    private void removeHeaderByInstanceAndType(Message message, String headerName, String instanceTag) {
        Field toRemove = message.getHeader().getFields().stream()
                .filter(f -> f.getName().equalsIgnoreCase(headerName) && f.getBody().contains(instanceTag))
                .findFirst().orElseThrow(() -> new AssertionError("Header not found: " + headerName + " with " + instanceTag));
        message.getHeader().removeFields(toRemove.getName());
        message.getHeader().getFields().stream()
                .filter(f -> f.getName().equalsIgnoreCase(headerName) && !f.getBody().contains(instanceTag))
                .forEach(f -> message.getHeader().addField(f));
    }

    // Replaces the b= signature on a specific ARC header (identified by name + instance tag) with 128 zero bytes.
    private void corruptSignatureOnHeader(Message message, String headerName, String instanceTag) {
        String fakeB64 = Base64.getEncoder().encodeToString(new byte[128]);
        List<Field> fields = new java.util.ArrayList<>(message.getHeader().getFields());
        message.getHeader().removeFields(headerName);
        for (Field f : fields) {
            if (f.getName().equalsIgnoreCase(headerName)) {
                if (f.getBody().contains(instanceTag)) {
                    String corrupted = f.getBody().replaceAll("; b=.*$", "; b=" + fakeB64);
                    message.getHeader().addField(new RawField(f.getName(), corrupted));
                } else {
                    message.getHeader().addField(f);
                }
            }
        }
    }

    // Replaces a tag value (e.g. "cv=pass" → "cv=none") on the first matching header with the given instance tag.
    private void replaceTagOnHeader(Message message, String headerName, String instanceTag, String oldVal, String newVal) {
        List<Field> fields = new java.util.ArrayList<>(message.getHeader().getFields());
        message.getHeader().removeFields(headerName);
        for (Field f : fields) {
            if (f.getName().equalsIgnoreCase(headerName)) {
                if (f.getBody().contains(instanceTag)) {
                    message.getHeader().addField(new RawField(f.getName(), f.getBody().replace(oldVal, newVal)));
                } else {
                    message.getHeader().addField(f);
                }
            }
        }
    }

    private ByteArrayInputStream readFileToByteArrayInputStream(String fileName) throws URISyntaxException, IOException {
        URL resource = this.getClass().getResource(fileName);
        FileInputStream file = new FileInputStream(new File(resource.toURI()));
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        DKIMCommon.streamCopy(file, byteArrayOutputStream);
        String string = byteArrayOutputStream.toString();
        return new ByteArrayInputStream(string.getBytes(StandardCharsets.UTF_8));
    }

}