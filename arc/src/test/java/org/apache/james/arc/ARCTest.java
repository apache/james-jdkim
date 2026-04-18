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

    private static final String VALIMAIL_DUMMY_PUBLIC_KEY =
            "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3id"
            + "Y6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lx"
            + "j+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB";
    private static final String VALIMAIL_512_PUBLIC_KEY =
            "v=DKIM1; k=rsa; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIWmlgix/84GJ+dfgjm7LTc9EPdfk"
            + "ftlgiPpCq4/kbDAZmU0VvYKDljjleJ1dfvS+CGy9U/kk1tG3EeEvb82xAcCAwEAAQ==";
    private static final String VALIMAIL_1024_PUBLIC_KEY =
            "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCyBwu6PiaDN87t3DVZ84zIrE"
            + "hCoxtFuv7g52oCwAUXTDnXZ+0XHM/rhkm8XSGr1yLsDc1zLGX8IfITY1dL2CzptdgyiX7vgYjzZqG368"
            + "C8BtGB5m6nj26NyhSKEdlV7MS9KbASd359ggCeGTT5QjRKEMSauVyVSeapq6ZcpZ9JwQIDAQAB";
    private static final String VALIMAIL_2048_PUBLIC_KEY =
            "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv+7VkwpTtICeJFM4Hf"
            + "UZsvv2OaA+QMrW9Af1PpTOzVP0uvUFK20lcaxMvt81ia/sGYW4gHp/WUIk0BIQMPVhUeCIuM1mcOQNFS"
            + "OflR8pLo916rjEZXpRP/XGo4HwWzdqD2qQeb3+fv1IrzfHiDb9THbamoz05EX7JX+wVSAhdSW/igwhA/"
            + "+beuzWR0RDDyGMT1b1Sb/lrGfwSXm7QoZQtj5PRiTX+fsL7WlzL+fBThySwS8ZBZcHcd8iWOSGKZ0gYK"
            + "zxyuOf8VCX71C4xDhahN+HXWZFn9TZb+uZX9m+WXM3t+P8CdfxsaOdnVg6imgNDlUWX4ClLTZhco0Kmi"
            + "BU+QIDAQAB";

    private final MockPublicKeyRecordRetrieverArc valimailKeyRecordRetriever = new MockPublicKeyRecordRetrieverArc(
            dmarcRetriever,
            MockPublicKeyRecordRetriever.Record.of("dummy", "example.org", VALIMAIL_DUMMY_PUBLIC_KEY)
    );

    private final MockPublicKeyRecordRetrieverArc valimailKeySizeRecordRetriever = new MockPublicKeyRecordRetrieverArc(
            dmarcRetriever,
            MockPublicKeyRecordRetriever.Record.of("dummy", "example.org", VALIMAIL_DUMMY_PUBLIC_KEY),
            MockPublicKeyRecordRetriever.Record.of("512", "example.org", VALIMAIL_512_PUBLIC_KEY),
            MockPublicKeyRecordRetriever.Record.of("1024", "example.org", VALIMAIL_1024_PUBLIC_KEY),
            MockPublicKeyRecordRetriever.Record.of("2048", "example.org", VALIMAIL_2048_PUBLIC_KEY)
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

    // ams_struct_i_na: an ARC-Message-Signature with no i= tag at all must be rejected.
    @Test
    public void validate_arc_chain_fails_when_ams_has_no_instance_tag() throws Exception {
        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        Message message = new DefaultMessageBuilder().parseMessage(emailStream);
        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);

        message.getHeader().addField(new RawField(ARC_AUTHENTICATION_RESULTS, arcSet.get(ARC_AUTHENTICATION_RESULTS)));
        message.getHeader().addField(new RawField(ARC_SEAL, arcSet.get(ARC_SEAL)));
        String malformedAms = arcSet.get(ARC_MESSAGE_SIGNATURE).replaceFirst("i=1;\\s*", "");
        message.getHeader().addField(new RawField(ARC_MESSAGE_SIGNATURE, malformedAms));

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // ams_struct_i_empty: an ARC-Message-Signature with i= but no value (i=;) must be rejected.
    @Test
    public void validate_arc_chain_fails_when_ams_has_empty_instance_tag() throws Exception {
        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        Message message = new DefaultMessageBuilder().parseMessage(emailStream);
        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);

        message.getHeader().addField(new RawField(ARC_AUTHENTICATION_RESULTS, arcSet.get(ARC_AUTHENTICATION_RESULTS)));
        message.getHeader().addField(new RawField(ARC_SEAL, arcSet.get(ARC_SEAL)));
        String malformedAms = arcSet.get(ARC_MESSAGE_SIGNATURE).replaceFirst("i=1;", "i=;");
        message.getHeader().addField(new RawField(ARC_MESSAGE_SIGNATURE, malformedAms));

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // ams_struct_i_zero: an ARC-Message-Signature with i=0 must be rejected — instance numbers start at 1.
    @Test
    public void validate_arc_chain_fails_when_ams_has_zero_instance_tag() throws Exception {
        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        Message message = new DefaultMessageBuilder().parseMessage(emailStream);
        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);

        message.getHeader().addField(new RawField(ARC_AUTHENTICATION_RESULTS, arcSet.get(ARC_AUTHENTICATION_RESULTS)));
        message.getHeader().addField(new RawField(ARC_SEAL, arcSet.get(ARC_SEAL)));
        String malformedAms = arcSet.get(ARC_MESSAGE_SIGNATURE).replaceFirst("i=1;", "i=0;");
        message.getHeader().addField(new RawField(ARC_MESSAGE_SIGNATURE, malformedAms));

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // ams_struct_i_invalid: an ARC-Message-Signature with a non-numeric i= value must be rejected.
    @Test
    public void validate_arc_chain_fails_when_ams_has_non_numeric_instance_tag() throws Exception {
        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        Message message = new DefaultMessageBuilder().parseMessage(emailStream);
        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);

        message.getHeader().addField(new RawField(ARC_AUTHENTICATION_RESULTS, arcSet.get(ARC_AUTHENTICATION_RESULTS)));
        message.getHeader().addField(new RawField(ARC_SEAL, arcSet.get(ARC_SEAL)));
        String malformedAms = arcSet.get(ARC_MESSAGE_SIGNATURE).replaceFirst("i=1;", "i=abc;");
        message.getHeader().addField(new RawField(ARC_MESSAGE_SIGNATURE, malformedAms));

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // ams_struct_dup: two ARC-Message-Signature headers both claiming i=1 make the set ambiguous and
    // must be rejected — each instance number must appear exactly once.
    @Test
    public void validate_arc_chain_fails_when_ams_is_duplicated_at_same_instance() throws Exception {
        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        Message message = new DefaultMessageBuilder().parseMessage(emailStream);
        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);

        for (Map.Entry<String, String> entry : arcSet.entrySet()) {
            message.getHeader().addField(new RawField(entry.getKey(), entry.getValue()));
        }
        // Add a second AMS header at i=1 — duplicates the instance number
        message.getHeader().addField(new RawField(ARC_MESSAGE_SIGNATURE, arcSet.get(ARC_MESSAGE_SIGNATURE)));

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // ams_fields_i_dup1: duplicate ARC-Message-Signature instance numbers must be rejected even
    // when the duplicate appears before the rest of the ARC set in header order.
    @Test
    public void validate_arc_chain_fails_when_duplicate_ams_instance_appears_before_arc_set() throws Exception {
        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        Message message = new DefaultMessageBuilder().parseMessage(emailStream);
        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);

        message.getHeader().addField(new RawField(ARC_MESSAGE_SIGNATURE, arcSet.get(ARC_MESSAGE_SIGNATURE)));
        for (Map.Entry<String, String> entry : arcSet.entrySet()) {
            message.getHeader().addField(new RawField(entry.getKey(), entry.getValue()));
        }

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // ams_fields_i_dup2: duplicate ARC-Message-Signature instance numbers must be rejected when
    // the duplicate appears after the existing AMS header.
    @Test
    public void validate_arc_chain_fails_when_duplicate_ams_instance_appears_after_arc_set() throws Exception {
        Message message = buildOneHopChainWithAms(ams -> ams, true);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // ams_fields_a_na: AMS without a= does not declare a supported signature algorithm.
    @Test
    public void validate_arc_chain_fails_when_ams_algorithm_tag_is_missing() throws Exception {
        Message message = buildOneHopChainWithAms(ams -> ams.replaceFirst("a=rsa-sha256;\\s*", ""), false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // ams_fields_a_empty: AMS with an empty a= does not declare a supported signature algorithm.
    @Test
    public void validate_arc_chain_fails_when_ams_algorithm_tag_is_empty() throws Exception {
        Message message = buildOneHopChainWithAms(ams -> ams.replace("a=rsa-sha256", "a="), false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // ams_fields_a_sha1: rsa-sha1 is not supported for AMS verification.
    @Test
    public void validate_arc_chain_fails_when_ams_algorithm_is_sha1() throws Exception {
        Message message = buildOneHopChainWithAms(ams -> ams.replace("a=rsa-sha256", "a=rsa-sha1"), false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // ams_fields_a_unknown: unknown AMS signature algorithms must be rejected.
    @Test
    public void validate_arc_chain_fails_when_ams_algorithm_is_unknown() throws Exception {
        Message message = buildOneHopChainWithAms(ams -> ams.replace("a=rsa-sha256", "a=ed25519-sha256"), false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // ams_fields_b_ignores_wsp: whitespace inside AMS b= must be ignored during base64 decode.
    @Test
    public void validate_arc_chain_passes_when_ams_signature_contains_whitespace() throws Exception {
        assertValimailFixturePasses(
                "MIME-Version: 1.0\n"
                + "Return-Path: <jqd@d1.example.org>\n"
                + "ARC-Seal: a=rsa-sha256;\n"
                + "    b=L8GsQ6v/7miEWKMGu16QVCPF6IT8j9+DV/ZHzgm86gi5m2JYAq+BlkmiIDofRPW+QzAq85\n"
                + "    2UlxwI2NZrhyAKgtM4FKO7+84P1eYwJKh57DZfCyUpqRx1Je2+vzT8ZggXQWYjFEu36MTDFX\n"
                + "    fRKVqPV3omyP+CFBzjJFFDLehJaPk=; cv=none; d=example.org; i=1; s=dummy;\n"
                + "    t=12345\n"
                + "ARC-Message-Signature: a=rsa-sha256;\n"
                + "    b=QsRzR /UqwRfVLBc1TnoQomlVw5qi6jp08q8lHpBSl4RehWyHQtY3uOIAGdghDk/mO+/Xpm\n"
                + "    9JA5UVrPyDV0f+2q/YAHuwvP11iCkBQkocmFvgTSxN8H+DwFFPrVVUudQYZV7UDDycXoM6UE\n"
                + "    cdfzLLzVNPOAHEDIi/uzoV4sUqZ18=;\n"
                + "    bh=KWSe46TZKCcDbH4klJPo+tjk5LWJnVRlP5pvjXFZYLQ=; c=relaxed/relaxed;\n"
                + "    d=example.org; h=from:to:date:subject:mime-version:arc-authentication-results;\n"
                + "    i=1; s=dummy; t=12345\n"
                + valimailCommonMessageTail());
    }

    // ams_fields_b_na: missing AMS b= leaves no message signature to verify and must be rejected.
    @Test
    public void validate_arc_chain_fails_when_ams_signature_tag_is_missing() throws Exception {
        Message message = buildOneHopChainWithAms(ams -> ams.replaceAll("; b=.*$", ""), false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // ams_fields_b_empty: empty AMS b= leaves no message signature to verify and must be rejected.
    @Test
    public void validate_arc_chain_fails_when_ams_signature_tag_is_empty() throws Exception {
        Message message = buildOneHopChainWithAms(ams -> ams.replaceAll("; b=.*$", "; b="), false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // ams_fields_b_base64: AMS b= must be base64.
    @Test
    public void validate_arc_chain_fails_when_ams_signature_is_not_base64() throws Exception {
        Message message = buildOneHopChainWithAms(ams -> ams.replaceAll("; b=.*$", "; b=not-base64!"), false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // ams_fields_b_mod_sig: a modified AMS signature must be rejected.
    @Test
    public void validate_arc_chain_fails_when_ams_signature_is_modified() throws Exception {
        Message message = buildOneHopChainWithAms(
                ams -> ams.replaceAll("; b=.*$", "; b=" + Base64.getEncoder().encodeToString(new byte[128])),
                false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // ams_fields_b_head_case: AMS relaxed canonicalization lowercases signed header names.
    @Test
    public void validate_arc_chain_passes_when_signed_header_name_case_changes() throws Exception {
        assertValimailFixturePasses(valimailAmsCanonicalizationMessage(
                "Received: from segv.d1.example (segv.d1.example [72.52.75.15])\n"
                + "    by lists.example.org (8.14.5/8.14.5) with ESMTP id t0EKaNU9010123\n"
                + "    for <arc@example.org>; Thu, 14 Jan 2015 15:01:30 -0800 (PST)\n"
                + "    (envelope-from jqd@d1.example)\n"
                + "Authentication-Results: lists.example.org;\n"
                + "    spf=pass smtp.mfrom=jqd@d1.example;\n"
                + "    dkim=pass (1024-bit key) header.i=@d1.example;\n"
                + "    dmarc=pass\n"
                + "Received: by 10.157.14.6 with HTTP; Tue, 3 Jan 2017 12:22:54 -0800 (PST)\n"
                + "Message-ID: <54B84785.1060301@d1.example.org>\n"
                + "Date: Thu, 14 Jan 2015 15:00:01 -0800\n"
                + "FROM: John Q Doe <jqd@d1.example.org>\n"
                + "To: arc@dmarc.org\n"
                + "Subject: Example 1\n"
                + "\n"
                + "Hey gang,\n"
                + "This is a test message.\n"
                + "--J."));
    }

    // ams_fields_b_head_unfold: folded signed headers must verify under relaxed canonicalization.
    @Test
    public void validate_arc_chain_passes_when_signed_header_is_folded() throws Exception {
        assertValimailFixturePasses(valimailAmsCanonicalizationMessage(
                "Received: from segv.d1.example (segv.d1.example [72.52.75.15])\n"
                + "    by lists.example.org (8.14.5/8.14.5) with ESMTP id t0EKaNU9010123\n"
                + "    for <arc@example.org>; Thu, 14 Jan 2015 15:01:30 -0800 (PST)\n"
                + "    (envelope-from jqd@d1.example)\n"
                + "Authentication-Results: lists.example.org;\n"
                + "    spf=pass smtp.mfrom=jqd@d1.example;\n"
                + "    dkim=pass (1024-bit key) header.i=@d1.example;\n"
                + "    dmarc=pass\n"
                + "Received: by 10.157.14.6 with HTTP; Tue, 3 Jan 2017 12:22:54 -0800 (PST)\n"
                + "Message-ID: <54B84785.1060301@d1.example.org>\n"
                + "Date: Thu, 14 Jan 2015 15:00:01 -0800\n"
                + "From: John Q Doe\n"
                + "  <jqd@d1.example.org>\n"
                + "To: arc@dmarc.org\n"
                + "Subject: Example 1\n"
                + "\n"
                + "Hey gang,\n"
                + "This is a test message.\n"
                + "--J."));
    }

    // ams_fields_b_eol_wsp: signed-header line-end whitespace must be stripped.
    @Test
    public void validate_arc_chain_passes_when_signed_header_has_end_of_line_whitespace() throws Exception {
        assertValimailFixturePasses(valimailAmsCanonicalizationMessage(
                "Received: from segv.d1.example (segv.d1.example [72.52.75.15])\n"
                + "    by lists.example.org (8.14.5/8.14.5) with ESMTP id t0EKaNU9010123\n"
                + "    for <arc@example.org>; Thu, 14 Jan 2015 15:01:30 -0800 (PST)\n"
                + "    (envelope-from jqd@d1.example)\n"
                + "Authentication-Results: lists.example.org;\n"
                + "    spf=pass smtp.mfrom=jqd@d1.example;\n"
                + "    dkim=pass (1024-bit key) header.i=@d1.example;\n"
                + "    dmarc=pass\n"
                + "Received: by 10.157.14.6 with HTTP; Tue, 3 Jan 2017 12:22:54 -0800 (PST)\n"
                + "Message-ID: <54B84785.1060301@d1.example.org>\n"
                + "Date: Thu, 14 Jan 2015 15:00:01 -0800\n"
                + "From: John Q Doe <jqd@d1.example.org>    \n"
                + "To: arc@dmarc.org\n"
                + "Subject: Example 1\n"
                + "\n"
                + "Hey gang,\n"
                + "This is a test message.\n"
                + "--J."));
    }

    // ams_fields_b_inl_wsp: repeated inline whitespace in signed headers must be reduced.
    @Test
    public void validate_arc_chain_passes_when_signed_header_has_extra_inline_whitespace() throws Exception {
        assertValimailFixturePasses(valimailAmsCanonicalizationMessage(
                "Received: from segv.d1.example (segv.d1.example [72.52.75.15])\n"
                + "    by lists.example.org (8.14.5/8.14.5) with ESMTP id t0EKaNU9010123\n"
                + "    for <arc@example.org>; Thu, 14 Jan 2015 15:01:30 -0800 (PST)\n"
                + "    (envelope-from jqd@d1.example)\n"
                + "Authentication-Results: lists.example.org;\n"
                + "    spf=pass smtp.mfrom=jqd@d1.example;\n"
                + "    dkim=pass (1024-bit key) header.i=@d1.example;\n"
                + "    dmarc=pass\n"
                + "Received: by 10.157.14.6 with HTTP; Tue, 3 Jan 2017 12:22:54 -0800 (PST)\n"
                + "Message-ID: <54B84785.1060301@d1.example.org>\n"
                + "Date: Thu, 14 Jan 2015 15:00:01 -0800\n"
                + "From: John   Q    Doe     <jqd@d1.example.org>\n"
                + "To: arc@dmarc.org\n"
                + "Subject: Example 1\n"
                + "\n"
                + "Hey gang,\n"
                + "This is a test message.\n"
                + "--J."));
    }

    // ams_fields_b_col_wsp: whitespace after signed-header colons must be stripped.
    @Test
    public void validate_arc_chain_passes_when_signed_headers_have_colon_whitespace() throws Exception {
        assertValimailFixturePasses(valimailAmsCanonicalizationMessage(
                "Received: from segv.d1.example (segv.d1.example [72.52.75.15])\n"
                + "    by lists.example.org (8.14.5/8.14.5) with ESMTP id t0EKaNU9010123\n"
                + "    for <arc@example.org>; Thu, 14 Jan 2015 15:01:30 -0800 (PST)\n"
                + "    (envelope-from jqd@d1.example)\n"
                + "Authentication-Results: lists.example.org;\n"
                + "    spf=pass smtp.mfrom=jqd@d1.example;\n"
                + "    dkim=pass (1024-bit key) header.i=@d1.example;\n"
                + "    dmarc=pass\n"
                + "Received: by 10.157.14.6 with HTTP; Tue, 3 Jan 2017 12:22:54 -0800 (PST)\n"
                + "Message-ID: <54B84785.1060301@d1.example.org>\n"
                + "Date:  Thu, 14 Jan 2015 15:00:01 -0800\n"
                + "From:  John Q Doe <jqd@d1.example.org>\n"
                + "To:   arc@dmarc.org\n"
                + "Subject: Example 1\n"
                + "\n"
                + "Hey gang,\n"
                + "This is a test message.\n"
                + "--J."));
    }

    // ams_fields_b_mod_headers1: modifying a signed From header must invalidate AMS.
    @Test
    public void validate_arc_chain_fails_when_signed_from_header_is_modified() throws Exception {
        assertValimailFixtureFails(valimailAmsCanonicalizationMessage(
                "Received: from segv.d1.example (segv.d1.example [72.52.75.15])\n"
                + "    by lists.example.org (8.14.5/8.14.5) with ESMTP id t0EKaNU9010123\n"
                + "    for <arc@example.org>; Thu, 14 Jan 2015 15:01:30 -0800 (PST)\n"
                + "    (envelope-from jqd@d1.example)\n"
                + "Authentication-Results: lists.example.org;\n"
                + "    spf=pass smtp.mfrom=jqd@d1.example;\n"
                + "    dkim=pass (1024-bit key) header.i=@d1.example;\n"
                + "    dmarc=pass\n"
                + "Received: by 10.157.14.6 with HTTP; Tue, 3 Jan 2017 12:22:54 -0800 (PST)\n"
                + "Message-ID: <54B84785.1060301@d1.example.org>\n"
                + "Date: Thu, 14 Jan 2015 15:00:01 -0800\n"
                + "From: Q Doe <jqd@d1.example.org>\n"
                + "To: arc@dmarc.org\n"
                + "Subject: Example 1\n"
                + "\n"
                + "Hey gang,\n"
                + "This is a test message.\n"
                + "--J."));
    }

    // ams_fields_b_mod_headers2: modifying a signed Subject header must invalidate AMS.
    @Test
    public void validate_arc_chain_fails_when_signed_subject_header_is_modified() throws Exception {
        assertValimailFixtureFails(valimailAmsCanonicalizationMessage(
                "Received: from segv.d1.example (segv.d1.example [72.52.75.15])\n"
                + "    by lists.example.org (8.14.5/8.14.5) with ESMTP id t0EKaNU9010123\n"
                + "    for <arc@example.org>; Thu, 14 Jan 2015 15:01:30 -0800 (PST)\n"
                + "    (envelope-from jqd@d1.example)\n"
                + "Authentication-Results: lists.example.org;\n"
                + "    spf=pass smtp.mfrom=jqd@d1.example;\n"
                + "    dkim=pass (1024-bit key) header.i=@d1.example;\n"
                + "    dmarc=pass\n"
                + "Received: by 10.157.14.6 with HTTP; Tue, 3 Jan 2017 12:22:54 -0800 (PST)\n"
                + "Message-ID: <54B84785.1060301@d1.example.org>\n"
                + "Date: Thu, 14 Jan 2015 15:00:01 -0800\n"
                + "From: John Q Doe <jqd@d1.example.org>\n"
                + "To: arc@dmarc.org\n"
                + "Subject: Example 1 (Mod)\n"
                + "\n"
                + "Hey gang,\n"
                + "This is a test message.\n"
                + "--J."));
    }

    // aar_struct_i_na / aar_i_missing: an ARC-Authentication-Results header without i= is invalid.
    @Test
    public void validate_arc_chain_fails_when_aar_has_no_instance_tag() throws Exception {
        Message message = buildOneHopChainWithAar("smtp.d1.example; arc=none", true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // aar_struct_i_empty: an ARC-Authentication-Results header with empty i= is invalid.
    @Test
    public void validate_arc_chain_fails_when_aar_has_empty_instance_tag() throws Exception {
        Message message = buildOneHopChainWithAar("i=; smtp.d1.example; arc=none", true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // aar_struct_i_zero: ARC instance numbers start at 1, so AAR i=0 is invalid.
    @Test
    public void validate_arc_chain_fails_when_aar_has_zero_instance_tag() throws Exception {
        Message message = buildOneHopChainWithAar("i=0; smtp.d1.example; arc=none", true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // aar_struct_invalid: AAR instance numbers must be numeric.
    @Test
    public void validate_arc_chain_fails_when_aar_has_non_numeric_instance_tag() throws Exception {
        Message message = buildOneHopChainWithAar("i=abc; smtp.d1.example; arc=none", true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // aar_struct_dup: duplicate ARC-Authentication-Results headers for the same instance are invalid.
    @Test
    public void validate_arc_chain_fails_when_aar_is_duplicated_at_same_instance() throws Exception {
        Message message = buildOneHopChainWithAar(null, true, true);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // aar_struct_missing / aar_missing: an ARC set with AMS and AS but no AAR is incomplete.
    @Test
    public void validate_arc_chain_fails_when_aar_header_is_missing() throws Exception {
        Message message = buildOneHopChainWithAar(null, false, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // aar_i_wrong: an AAR whose i= does not match the rest of its ARC set is invalid.
    @Test
    public void validate_arc_chain_fails_when_aar_instance_does_not_match_arc_set() throws Exception {
        Message message = buildOneHopChainWithAar("i=2; smtp.d1.example; arc=none", true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // aar_i_not_prefixed: the AAR i= tag must be the leading ARC instance component.
    @Test
    public void validate_arc_chain_fails_when_aar_instance_tag_is_not_prefixed() throws Exception {
        Message message = buildOneHopChainWithAar("smtp.d1.example; i=1; arc=none", true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // aar_i_no_semi: the AAR i= value must be followed by a semicolon separator.
    @Test
    public void validate_arc_chain_fails_when_aar_instance_tag_has_no_semicolon() throws Exception {
        Message message = buildOneHopChainWithAar("i=1 smtp.d1.example; arc=none", true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // aar2_missing: in a two-hop chain, the latest ARC set is incomplete if its i=2 AAR is missing.
    @Test
    public void validate_arc_chain_fails_when_i2_aar_header_is_missing() throws Exception {
        Message message = buildNHopChain(2);
        removeHeaderByInstanceAndType(message, ARC_AUTHENTICATION_RESULTS, "i=2");

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // ams_struct_missing: an ARC-Seal at i=1 with no corresponding ARC-Message-Signature means the
    // set is incomplete and must be rejected — covered by validate_arc_chain_fails_when_ams_header_is_missing.

    // Pre-filled template used for direct ARCSigner canonicalization tests.
    private static final String CANON_TEST_TEMPLATE =
            "i=1; a=rsa-sha256; c=relaxed/relaxed; d=dmarc.example; s=arc; t=" + TIMESTAMP
            + "; h=Subject:From:To; bh=; b=";

    // Minimal base email used for canonicalization tests.
    private static final String BASE_EMAIL =
            "From: jqd@d1.example\r\n"
            + "To: arc@example.com\r\n"
            + "Subject: test\r\n"
            + "\r\n"
            + "Hello world\r\n";

    // Signs a raw email byte string directly with ARCSigner and returns "ARC-element:<ams body>".
    private String signRawEmail(String rawEmail) {
        ARCSigner signer = new ARCSigner(CANON_TEST_TEMPLATE, ArcTestKeys.privateKeyArc);
        return signer.generateAms(new ByteArrayInputStream(rawEmail.getBytes(StandardCharsets.UTF_8)));
    }

    // Extracts a tag value from an AMS record (with or without the "ARC-element:" prefix).
    private String extractAmsTag(String ams, String tagName) {
        String body = ams.replaceFirst("^ARC-element:", "");
        for (String part : body.split(";")) {
            String t = part.trim();
            if (t.startsWith(tagName + "=")) {
                return t.substring((tagName + "=").length()).trim();
            }
        }
        return null;
    }

    // message_body_eol_wsp: trailing whitespace on a body line must be stripped before body hashing,
    // so two messages that differ only in trailing spaces produce the same bh=.
    @Test
    public void body_hash_is_invariant_under_body_line_trailing_whitespace() {
        String variant = BASE_EMAIL.replace("Hello world\r\n", "Hello world   \r\n");
        assertThat(extractAmsTag(signRawEmail(BASE_EMAIL), "bh"))
                .isEqualTo(extractAmsTag(signRawEmail(variant), "bh"));
    }

    // message_body_inl_wsp: runs of whitespace inside a body line must be collapsed to one space
    // before body hashing, so double spaces produce the same bh= as single spaces.
    @Test
    public void body_hash_is_invariant_under_body_inline_whitespace() {
        String variant = BASE_EMAIL.replace("Hello world\r\n", "Hello  world\r\n");
        assertThat(extractAmsTag(signRawEmail(BASE_EMAIL), "bh"))
                .isEqualTo(extractAmsTag(signRawEmail(variant), "bh"));
    }

    // message_body_end_lines: trailing blank lines at the end of the body must be ignored when
    // computing the body hash, so extra blank lines produce the same bh=.
    @Test
    public void body_hash_is_invariant_under_trailing_blank_lines() {
        String variant = BASE_EMAIL.replace("Hello world\r\n", "Hello world\r\n\r\n\r\n");
        assertThat(extractAmsTag(signRawEmail(BASE_EMAIL), "bh"))
                .isEqualTo(extractAmsTag(signRawEmail(variant), "bh"));
    }

    // message_body_trail_crlf: a body that does not end with CRLF must have one appended before
    // hashing, so it produces the same bh= as the same body that does end with CRLF.
    @Test
    public void body_hash_is_invariant_when_body_lacks_trailing_crlf() {
        String variant = BASE_EMAIL.replace("Hello world\r\n", "Hello world");
        assertThat(extractAmsTag(signRawEmail(BASE_EMAIL), "bh"))
                .isEqualTo(extractAmsTag(signRawEmail(variant), "bh"));
    }

    // headers_field_name_case: header names must be lowercased before signing, so Subject and SUBJECT
    // produce the same AMS (same bh= and same b=).
    @Test
    public void ams_is_invariant_under_header_name_case() {
        String variant = BASE_EMAIL.replace("Subject: test\r\n", "SUBJECT: test\r\n");
        assertThat(signRawEmail(BASE_EMAIL)).isEqualTo(signRawEmail(variant));
    }

    // headers_field_unfold: folded headers (split with CRLF + whitespace continuation) must be
    // joined back into one line before signing, so the folded and unfolded forms produce the same AMS.
    @Test
    public void ams_is_invariant_under_header_folding() {
        String cleanEmail =
                "From: jqd@d1.example\r\nTo: arc@example.com\r\nSubject: Hello world\r\n\r\nHello world\r\n";
        String foldedEmail =
                "From: jqd@d1.example\r\nTo: arc@example.com\r\nSubject: Hello\r\n world\r\n\r\nHello world\r\n";
        assertThat(signRawEmail(cleanEmail)).isEqualTo(signRawEmail(foldedEmail));
    }

    // headers_eol_wsp: trailing whitespace at the end of a header value must be stripped before
    // signing, so trailing spaces produce the same AMS as no trailing spaces.
    @Test
    public void ams_is_invariant_under_header_trailing_whitespace() {
        String variant = BASE_EMAIL.replace("Subject: test\r\n", "Subject: test   \r\n");
        assertThat(signRawEmail(BASE_EMAIL)).isEqualTo(signRawEmail(variant));
    }

    // headers_inl_wsp: runs of whitespace inside a header value must be collapsed to one space before
    // signing, so double spaces inside a value produce the same AMS as a single space.
    @Test
    public void ams_is_invariant_under_header_inline_whitespace() {
        String cleanEmail =
                "From: jqd@d1.example\r\nTo: arc@example.com\r\nSubject: Hello world\r\n\r\nHello world\r\n";
        String variantEmail =
                "From: jqd@d1.example\r\nTo: arc@example.com\r\nSubject: Hello  world\r\n\r\nHello world\r\n";
        assertThat(signRawEmail(cleanEmail)).isEqualTo(signRawEmail(variantEmail));
    }

    // headers_col_wsp: whitespace around the colon separator in a header must be normalised before
    // signing, so "Subject: test" and "Subject:test" (no space) produce the same AMS.
    @Test
    public void ams_is_invariant_under_header_colon_whitespace() {
        String variant = BASE_EMAIL.replace("Subject: test\r\n", "Subject:test\r\n");
        assertThat(signRawEmail(BASE_EMAIL)).isEqualTo(signRawEmail(variant));
    }

    // i1_base: when a message already carries a valid i=1 ARC set, buildArcSet must produce an i=2 set
    // whose seal carries cv=pass — the new server correctly extends the chain.
    @Test
    public void build_arc_set_generates_i2_cv_pass_when_signing_on_top_of_valid_i1_chain() throws Exception {
        Message message = buildNHopChain(1);
        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);
        assertThat(arcSet.get(ARC_SEAL)).contains("cv=pass");
        assertThat(arcSet.get(ARC_SEAL)).contains("i=2");
        assertThat(arcSet.get(ARC_MESSAGE_SIGNATURE)).contains("i=2");
        assertThat(arcSet.get(ARC_AUTHENTICATION_RESULTS)).contains("i=2");
    }

    // i2_base: when a message already carries valid i=1 and i=2 ARC sets, buildArcSet must produce an i=3
    // set whose seal carries cv=pass — the new server correctly extends the chain.
    @Test
    public void build_arc_set_generates_i3_cv_pass_when_signing_on_top_of_valid_i2_chain() throws Exception {
        Message message = buildNHopChain(2);
        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);
        assertThat(arcSet.get(ARC_SEAL)).contains("cv=pass");
        assertThat(arcSet.get(ARC_SEAL)).contains("i=3");
        assertThat(arcSet.get(ARC_MESSAGE_SIGNATURE)).contains("i=3");
        assertThat(arcSet.get(ARC_AUTHENTICATION_RESULTS)).contains("i=3");
    }

    // i1_base_fail: when the incoming i=1 chain is already broken (corrupt AMS), buildArcSet must still
    // produce an i=2 set, but the new seal must carry cv=fail to faithfully record the broken chain.
    @Test
    public void build_arc_set_generates_cv_fail_seal_when_signing_on_top_of_broken_i1_chain() throws Exception {
        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        Message message = new DefaultMessageBuilder().parseMessage(emailStream);
        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);

        String fakeB64 = Base64.getEncoder().encodeToString(new byte[128]);
        for (Map.Entry<String, String> entry : arcSet.entrySet()) {
            String value = entry.getKey().equals(ARC_MESSAGE_SIGNATURE)
                    ? entry.getValue().replaceAll("; b=.*$", "; b=" + fakeB64)
                    : entry.getValue();
            message.getHeader().addField(new RawField(entry.getKey(), value));
        }

        Map<String, String> newArcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);
        assertThat(newArcSet.get(ARC_SEAL)).contains("cv=fail");
        assertThat(newArcSet.get(ARC_SEAL)).contains("i=2");
    }

    // i2_base_fail: when the incoming two-hop chain is already broken, buildArcSet must produce an i=3
    // set whose seal carries cv=fail — the broken state is faithfully recorded.
    @Test
    public void build_arc_set_generates_cv_fail_seal_when_signing_on_top_of_broken_i2_chain() throws Exception {
        Message message = buildNHopChain(2);
        corruptSignatureOnHeader(message, ARC_MESSAGE_SIGNATURE, "i=1");

        Map<String, String> newArcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);
        assertThat(newArcSet.get(ARC_SEAL)).contains("cv=fail");
        assertThat(newArcSet.get(ARC_SEAL)).contains("i=3");
    }

    // no_additional_sig: after signing on top of a broken chain and adding the new i=2 set to the message,
    // the full chain validation must still return cv=fail — a valid new signature must not heal a broken chain.
    @Test
    public void validate_arc_chain_remains_fail_after_signing_on_top_of_broken_chain() throws Exception {
        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        Message message = new DefaultMessageBuilder().parseMessage(emailStream);
        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);

        String fakeB64 = Base64.getEncoder().encodeToString(new byte[128]);
        for (Map.Entry<String, String> entry : arcSet.entrySet()) {
            String value = entry.getKey().equals(ARC_MESSAGE_SIGNATURE)
                    ? entry.getValue().replaceAll("; b=.*$", "; b=" + fakeB64)
                    : entry.getValue();
            message.getHeader().addField(new RawField(entry.getKey(), value));
        }

        Map<String, String> newArcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);
        for (Map.Entry<String, String> entry : newArcSet.entrySet()) {
            message.getHeader().addField(new RawField(entry.getKey(), entry.getValue()));
        }

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // ar_merged1: multiple Authentication-Results headers for the signing authserv-id must be
    // consolidated into one ARC-Authentication-Results header, while other authserv-ids are ignored.
    @Test
    public void build_arc_set_merges_multiple_authentication_results_for_authserv_id() throws Exception {
        Message message = parseRawEmail(
                "Authentication-Results: lists.example.org; arc=none\n"
                + "Authentication-Results: lists.example.org; spf=pass smtp.mfrom=jqd@d1.example\n"
                + "Authentication-Results: lists.example.org; dkim=pass (1024-bit key) header.i=@d1.example\n"
                + "Authentication-Results: lists.example.org; dmarc=pass\n"
                + "Authentication-Results: nobody.example.org; something=ignored\n"
                + basicMessageWithoutAuthenticationResults());

        Map<String, String> arcSet = buildArcSetWithAuthService(message, "lists.example.org");

        assertThat(arcSet.get(ARC_AUTHENTICATION_RESULTS)).isEqualTo(
                "i=1; lists.example.org; arc=none; spf=pass smtp.mfrom=jqd@d1.example; "
                + "dkim=pass (1024-bit key) header.i=@d1.example; dmarc=pass");
    }

    // ar_merged2: folded Authentication-Results payloads must be unfolded and merged in order.
    @Test
    public void build_arc_set_merges_folded_authentication_results_for_authserv_id() throws Exception {
        Message message = parseRawEmail(
                "Authentication-Results: lists.example.org; arc=none;\n"
                + "  spf=pass smtp.mfrom=jqd@d1.example\n"
                + "Authentication-Results: lists.example.org; dkim=pass (1024-bit key) header.i=@d1.example\n"
                + "Authentication-Results: lists.example.org; dmarc=pass\n"
                + "Authentication-Results: nobody.example.org; something=ignored\n"
                + basicMessageWithoutAuthenticationResults());

        Map<String, String> arcSet = buildArcSetWithAuthService(message, "lists.example.org");

        assertThat(arcSet.get(ARC_AUTHENTICATION_RESULTS)).isEqualTo(
                "i=1; lists.example.org; arc=none; spf=pass smtp.mfrom=jqd@d1.example; "
                + "dkim=pass (1024-bit key) header.i=@d1.example; dmarc=pass");
    }

    // ams_format_tags_unknown: an unrecognised tag in the ARC-Message-Signature must be silently ignored,
    // so a chain signed with an extra z= tag must still validate as cv=pass.
    @Test
    public void validate_arc_chain_passes_when_ams_has_unknown_tag() throws Exception {
        String templateWithUnknownTag = "i=; a=rsa-sha256; c=relaxed/relaxed; d=dmarc.example; s=arc; z=test; t=; h=Subject:From:To; bh=; b=";
        ArcSetBuilder builderWithUnknownTag = new ArcSetBuilder(ArcTestKeys.privateKeyArc, templateWithUnknownTag, ARC_SEAL_TEMPLATE, AUTH_SERVICE, TIMESTAMP);

        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        Message message = new DefaultMessageBuilder().parseMessage(emailStream);
        Map<String, String> arcSet = builderWithUnknownTag.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);
        for (Map.Entry<String, String> entry : arcSet.entrySet()) {
            message.getHeader().addField(new RawField(entry.getKey(), entry.getValue()));
        }

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("pass");
    }

    // ams_format_inv_tag_key: a tag key starting with a digit (e.g. 1s=arc) is not a valid tag name
    // and the selector cannot be resolved, so the chain must be rejected.
    @Test
    public void validate_arc_chain_fails_when_ams_has_invalid_tag_key_character() throws Exception {
        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        Message message = new DefaultMessageBuilder().parseMessage(emailStream);
        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);

        message.getHeader().addField(new RawField(ARC_AUTHENTICATION_RESULTS, arcSet.get(ARC_AUTHENTICATION_RESULTS)));
        message.getHeader().addField(new RawField(ARC_SEAL, arcSet.get(ARC_SEAL)));
        String malformedAms = arcSet.get(ARC_MESSAGE_SIGNATURE).replace("s=arc", "1s=arc");
        message.getHeader().addField(new RawField(ARC_MESSAGE_SIGNATURE, malformedAms));

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // ams_format_tags_dup: if the same tag key appears twice in an ARC-Message-Signature, the second
    // value overrides the first, resolving to a different selector that is not in DNS, causing failure.
    @Test
    public void validate_arc_chain_fails_when_ams_has_duplicate_tag() throws Exception {
        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        Message message = new DefaultMessageBuilder().parseMessage(emailStream);
        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);

        message.getHeader().addField(new RawField(ARC_AUTHENTICATION_RESULTS, arcSet.get(ARC_AUTHENTICATION_RESULTS)));
        message.getHeader().addField(new RawField(ARC_SEAL, arcSet.get(ARC_SEAL)));
        String malformedAms = arcSet.get(ARC_MESSAGE_SIGNATURE) + "; s=invalid";
        message.getHeader().addField(new RawField(ARC_MESSAGE_SIGNATURE, malformedAms));

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // ams_format_tags_key_case: tag keys are case-sensitive — S=arc does not provide the s= tag,
    // so the selector cannot be found and the chain must be rejected.
    @Test
    public void validate_arc_chain_fails_when_ams_uses_uppercase_tag_key() throws Exception {
        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        Message message = new DefaultMessageBuilder().parseMessage(emailStream);
        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);

        message.getHeader().addField(new RawField(ARC_AUTHENTICATION_RESULTS, arcSet.get(ARC_AUTHENTICATION_RESULTS)));
        message.getHeader().addField(new RawField(ARC_SEAL, arcSet.get(ARC_SEAL)));
        String malformedAms = arcSet.get(ARC_MESSAGE_SIGNATURE).replace("s=arc", "S=arc");
        message.getHeader().addField(new RawField(ARC_MESSAGE_SIGNATURE, malformedAms));

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // ams_format_tags_val_case: modifying a tag value's case (e.g. a=RSA-SHA256) changes the
    // signed bytes so the signature no longer verifies, and the chain must be rejected.
    @Test
    public void validate_arc_chain_fails_when_ams_tag_value_has_wrong_case() throws Exception {
        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        Message message = new DefaultMessageBuilder().parseMessage(emailStream);
        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);

        message.getHeader().addField(new RawField(ARC_AUTHENTICATION_RESULTS, arcSet.get(ARC_AUTHENTICATION_RESULTS)));
        message.getHeader().addField(new RawField(ARC_SEAL, arcSet.get(ARC_SEAL)));
        String malformedAms = arcSet.get(ARC_MESSAGE_SIGNATURE).replace("a=rsa-sha256", "a=RSA-SHA256");
        message.getHeader().addField(new RawField(ARC_MESSAGE_SIGNATURE, malformedAms));

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // ams_format_tags_wsp: whitespace inside a tag value (s=ar c) changes the DNS selector name to
    // one that does not exist, so the public key cannot be retrieved and the chain must be rejected.
    @Test
    public void validate_arc_chain_fails_when_ams_tag_value_contains_whitespace() throws Exception {
        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        Message message = new DefaultMessageBuilder().parseMessage(emailStream);
        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);

        message.getHeader().addField(new RawField(ARC_AUTHENTICATION_RESULTS, arcSet.get(ARC_AUTHENTICATION_RESULTS)));
        message.getHeader().addField(new RawField(ARC_SEAL, arcSet.get(ARC_SEAL)));
        String malformedAms = arcSet.get(ARC_MESSAGE_SIGNATURE).replace("s=arc", "s=ar c");
        message.getHeader().addField(new RawField(ARC_MESSAGE_SIGNATURE, malformedAms));

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // ams_format_tags_sc: an extra semicolon inside a tag value splits the value, making the s= tag
    // resolve to a truncated selector that is not in DNS, so the chain must be rejected.
    @Test
    public void validate_arc_chain_fails_when_ams_tag_value_contains_semicolon() throws Exception {
        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        Message message = new DefaultMessageBuilder().parseMessage(emailStream);
        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);

        message.getHeader().addField(new RawField(ARC_AUTHENTICATION_RESULTS, arcSet.get(ARC_AUTHENTICATION_RESULTS)));
        message.getHeader().addField(new RawField(ARC_SEAL, arcSet.get(ARC_SEAL)));
        String malformedAms = arcSet.get(ARC_MESSAGE_SIGNATURE).replace("s=arc", "s=ar;c");
        message.getHeader().addField(new RawField(ARC_MESSAGE_SIGNATURE, malformedAms));

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // ams_format_sc_wsp: whitespace before the semicolon separator in an AMS tag list is valid.
    // This mirrors the ValiMail arc_test_suite fixture and must validate as cv=pass.
    @Test
    public void validate_arc_chain_passes_when_ams_has_whitespace_around_semicolon_separator() throws Exception {
        assertValimailFixturePasses(
                "MIME-Version: 1.0\n"
                + "Return-Path: <jqd@d1.example.org>\n"
                + "ARC-Seal: a=rsa-sha256;\n"
                + "    b=OeNJ7p2NdW3mKv4hyenx+QbRuqqq8iwGAyY1WVX/EJiPHS2vNB5lEI/YmVB3diTkKPHWe8\n"
                + "    ZOq18DTVtOVuahLqM7s/4K/gvx3zal0vcedPL/mtRW4A1Ct0/wyLuFADX2HZ815cELx81SuX\n"
                + "    3fEbbym1br+0JArsz6n8798lidnWY=; cv=none; d=example.org; i=1; s=dummy;\n"
                + "    t=12345\n"
                + "ARC-Message-Signature: a=rsa-sha256;\n"
                + "    b=NOLE9bNh30qiTx35h5yKbHlDPahxvhXUWjv8Yiy5L7Ks3NNznK54dmUPZ4D/80tkRYiil0\n"
                + "    8sCqFTh7OH5ZTXXEfArxBMQQl3DAqTjOJQ1c3jPYwaDliWqCLLueSsH+ovaFGRGNPm2O41o0\n"
                + "    J8xUmyji1bXXLKMinB+Adv9ALXsw8=;\n"
                + "    bh=KWSe46TZKCcDbH4klJPo+tjk5LWJnVRlP5pvjXFZYLQ= ; c=relaxed/relaxed;\n"
                + "    d=example.org; h=from:to:date:subject:mime-version:arc-authentication-results;\n"
                + "    i=1; s=dummy; t=12345\n"
                + valimailCommonMessageTail());
    }

    // ams_format_eq_wsp: whitespace around "=" in an AMS tag is valid and should not break parsing.
    @Test
    public void validate_arc_chain_passes_when_ams_has_whitespace_around_equals_separator() throws Exception {
        assertValimailFixturePasses(
                "MIME-Version: 1.0\n"
                + "Return-Path: <jqd@d1.example.org>\n"
                + "ARC-Seal: a=rsa-sha256;\n"
                + "    b=CcoQW04QZ7n7OTPACcP26R0vJtjEwVmcFpj4+PJnvT1kVeOMfcqwt7FEGlCjeJ0QIYMeNW\n"
                + "    TY6kND0fe0WJDVnWvhCyeOb5JjwllbJJ/ThP74I5UPgQ0Cwp1h/O9HIrUJkrje6HQ3nD6Dok\n"
                + "    la2keL/t4R7YtMyAmn9sPWuAOwSrE=; cv=none; d=example.org; i=1; s=dummy;\n"
                + "    t=12345\n"
                + "ARC-Message-Signature: a=rsa-sha256;\n"
                + "    b=KLZ8Io9rZzsWt0Q/Mrx8sYO7HPLptFwGoCdabHuyrQsek+1c5yo5tOQidcTc8ksw5PoAZH\n"
                + "    PNOIoyGVte9jMk0LdA1IYjjvvUmEANMZCJf0wm66exDWJ30xMrgbosLN2XvsRk3BDkoCg2AY\n"
                + "    HkR11isMdIhrefd7AHw9YEDTnohQw=;\n"
                + "    bh=KWSe46TZKCcDbH4klJPo+tjk5LWJnVRlP5pvjXFZYLQ=; c = relaxed/relaxed;\n"
                + "    d=example.org; h=from:to:date:subject:mime-version:arc-authentication-results;\n"
                + "    i=1; s=dummy; t=12345\n"
                + valimailCommonMessageTail());
    }

    // ams_format_tags_trail_sc: a trailing semicolon at the end of the AMS tag list is valid.
    @Test
    public void validate_arc_chain_passes_when_ams_tag_list_has_trailing_semicolon() throws Exception {
        assertValimailFixturePasses(
                "MIME-Version: 1.0\n"
                + "Return-Path: <jqd@d1.example.org>\n"
                + "ARC-Seal: a=rsa-sha256;\n"
                + "    b=Q3iCsG7zmlydzz8zFIm4X+Nyr2636znsyGh+lRhCFtcWbw3m3v8fFrtK3uNvqSM+WW3Cmf\n"
                + "    TbteHFaG9YL34KUMi/ThuPoG8sOwJ18BPjXrdBS5EiXYBBFalkVRV0ktqyiNi57LBVS+VGWV\n"
                + "    FwOD85C/V/Fju2wETdy0ly1VjfLBg=; cv=none; d=example.org; i=1; s=dummy;\n"
                + "    t=12345\n"
                + "ARC-Message-Signature: a=rsa-sha256;\n"
                + "    b=H+XsRP2HBJwygQonE/YquKr2y1KqjjlhBQ/hEkIGFjjNhOIvMfuuO054H4+kxMmvHFdwk8\n"
                + "    a8Uwy1MxQBC3a4b0jAQ77rOn5VFhO1tAmCkfZP1bJSxewRfC2Eo7j/07+r8ZLuyuAzlQIW+n\n"
                + "    DPJtOhnIIEOGhLgPNlcTwc9R/XKiE=;\n"
                + "    bh=KWSe46TZKCcDbH4klJPo+tjk5LWJnVRlP5pvjXFZYLQ=; c=relaxed/relaxed;\n"
                + "    d=example.org; h=from:to:date:subject:mime-version:arc-authentication-results;\n"
                + "    i=1; s=dummy; t=12345;\n"
                + valimailCommonMessageTail());
    }

    // as_struct_i_na / as_fields_i_missing: an ARC-Seal without i= is invalid.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_has_no_instance_tag() throws Exception {
        Message message = buildOneHopChainWithSeal(
                seal -> seal.replaceFirst("i=1;\\s*", ""),
                true,
                false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_struct_i_empty: an ARC-Seal with empty i= is invalid.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_has_empty_instance_tag() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replaceFirst("i=1;", "i=;"), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_struct_i_zero: ARC instance numbers start at 1, so AS i=0 is invalid.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_has_zero_instance_tag() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replaceFirst("i=1;", "i=0;"), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_struct_i_invalid: ARC-Seal instance numbers must be numeric.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_has_non_numeric_instance_tag() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replaceFirst("i=1;", "i=abc;"), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_struct_dup: duplicate ARC-Seal headers for the same instance are invalid.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_is_duplicated_at_same_instance() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal, true, true);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_struct_missing: an ARC set with AAR and AMS but no AS is incomplete.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_header_is_missing_from_arc_set() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal, false, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_format_sc_wsp: whitespace before an AS semicolon separator is valid.
    @Test
    public void validate_arc_chain_passes_when_arc_seal_has_whitespace_around_semicolon_separator() throws Exception {
        assertValimailFixturePasses(
                "MIME-Version: 1.0\n"
                + "Return-Path: <jqd@d1.example.org>\n"
                + "ARC-Seal: a=rsa-sha256;\n"
                + "    b=sQHCWC9A8lAbvcPG+3jfih4lRJY/A0OI/GBGE4AYHf8u9cgsxOvyCqDWF3mr91HE5PhNh4\n"
                + "    RZW95NC6qhxEhnXLaXswqco2JXMVR6/rM5Q49bDE2RtlNen7wubw56NoJD2A7IGUSOzHaAiJ\n"
                + "    QhRTSoyG5OwNBC8+GlugUJi5mmZNU=; cv=none; d=example.org; i=1 ; s=dummy;\n"
                + "    t=12345\n"
                + valimailArcSealFormatCommonTail());
    }

    // as_format_eq_wsp: whitespace around "=" in the AS i= tag is valid.
    @Test
    public void validate_arc_chain_passes_when_arc_seal_has_whitespace_around_equals_separator() throws Exception {
        assertValimailFixturePasses(
                "MIME-Version: 1.0\n"
                + "Return-Path: <jqd@d1.example.org>\n"
                + "ARC-Seal: a=rsa-sha256;\n"
                + "    b=u4XUza5aJKdMCwCMffAieua1x4N9tZpKlx7UwMcdgV+BuIZc48C3rF8xu6BnoRQCaulZmW\n"
                + "    4EYspmshC6cGg+kmYaWR/sbW712Ag8W33enEcoh35XLTg9QHg7zWvftk746RrVFb5Ch8iRsU\n"
                + "    PJ0gkAieomzXwlqCIBZQD5Yz2LB38=; cv=none; d=example.org; i = 1; s=dummy;\n"
                + "    t=12345\n"
                + valimailArcSealFormatCommonTail());
    }

    // as_format_tags_trail_sc: a trailing semicolon at the end of the AS tag list is valid.
    @Test
    public void validate_arc_chain_passes_when_arc_seal_tag_list_has_trailing_semicolon() throws Exception {
        assertValimailFixturePasses(
                "MIME-Version: 1.0\n"
                + "Return-Path: <jqd@d1.example.org>\n"
                + "ARC-Seal: a=rsa-sha256;\n"
                + "    b=AcBD4PAxYztV5R8jYyYXKuMBWBRja89F6yBTQVtQ1FFUxQVYGOrFlnh3/r8/YtFt13NELg\n"
                + "    FpYeY3gnzudk30PoZZvM2MG9h07ByTgl0lSEsRLhN+ZtqoHRq1QGdW8oqOXntI51FbKwBdoe\n"
                + "    cHtLh18GzKAvazRWzv8//vQInYp/Y=; cv=none; d=example.org; i=1; s=dummy;\n"
                + "    t=12345;\n"
                + valimailArcSealFormatCommonTail());
    }

    // as_format_tags_unknown: an unknown AS tag is valid when it was present at signing time.
    @Test
    public void validate_arc_chain_passes_when_arc_seal_has_unknown_tag() throws Exception {
        assertValimailFixturePasses(
                "MIME-Version: 1.0\n"
                + "Return-Path: <jqd@d1.example.org>\n"
                + "ARC-Seal: a=rsa-sha256;\n"
                + "    b=FriX6cOxgBHhZwNYHn0KXSWVqwHPNV6sRAKUy9iN1OqwvAK9USwMsg/P08yXrUH8LRaijm\n"
                + "    msJjp0KUFYiffoQrhsxHwv1hJIGceJZB7lOFeZn7Z5aym4eBp7q7idwNyIaGKL7E0WzVkeAT\n"
                + "    RQ5LhtOInN23gugfmW6z8MUUvow5Y=; cv=none; d=example.org; i=1; s=dummy;\n"
                + "    t=12345; w=catparty\n"
                + valimailArcSealFormatCommonTail());
    }

    // as_format_inv_tag_key: invalid AS tag keys are rejected.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_has_invalid_tag_key_character() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replace("t=1755918846", "_=; t=1755918846"), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_format_tags_dup: duplicate AS tags are rejected.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_has_duplicate_tag() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal + "; s=invalid", true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_format_tags_key_case: AS tag keys are case-sensitive.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_uses_uppercase_tag_key() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replace("s=arc", "S=arc"), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_format_tags_val_case: AS domain value changes are signature-sensitive and must fail.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_tag_value_has_wrong_case() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replace("d=dmarc.example", "d=Dmarc.example"), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_format_tags_wsp: invalid whitespace inside an AS tag value must fail.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_tag_value_contains_whitespace() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replace("t=1755918846", "t=1755 918846"), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_format_tags_sc: an extra semicolon inside the AS tag list must fail.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_tag_value_contains_semicolon() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replace("s=arc", "s=arc;"), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_fields_i_dup: duplicate ARC-Seal headers at i=1 must be rejected.
    @Test
    public void validate_arc_chain_fails_when_i1_arc_seal_field_is_duplicated() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal, true, true);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_fields_i_dup2: duplicate ARC-Seal headers at i=2 must be rejected.
    @Test
    public void validate_arc_chain_fails_when_i2_arc_seal_field_is_duplicated() throws Exception {
        Message message = buildNHopChain(2);
        Field seal = message.getHeader().getFields().stream()
                .filter(f -> f.getName().equalsIgnoreCase(ARC_SEAL) && f.getBody().contains("i=2"))
                .findFirst().orElseThrow(() -> new AssertionError("i=2 ARC-Seal not found"));
        message.getHeader().addField(new RawField(ARC_SEAL, seal.getBody()));

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_fields_a_na: missing ARC-Seal a= changes the sealed data and must be rejected.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_algorithm_tag_is_missing() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replaceFirst("a=rsa-sha256;\\s*", ""), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_fields_a_empty: empty ARC-Seal a= changes the sealed data and must be rejected.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_algorithm_tag_is_empty() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replace("a=rsa-sha256", "a="), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_fields_a_sha1: changing ARC-Seal a= to rsa-sha1 invalidates the seal.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_algorithm_is_sha1() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replace("a=rsa-sha256", "a=rsa-sha1"), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_fields_a_unknown: unknown ARC-Seal algorithms must be rejected.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_algorithm_is_unknown() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replace("a=rsa-sha256", "a=ed25519-sha256"), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_fields_b_ignores_wsp: whitespace inside ARC-Seal b= must be ignored during base64 decode.
    @Test
    public void validate_arc_chain_passes_when_arc_seal_signature_contains_whitespace() throws Exception {
        Message message = buildOneHopChainWithSeal(this::insertWhitespaceIntoSealSignature, true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("pass");
    }

    // as_fields_b_1024: ARC-Seal signed with a 1024-bit RSA key must validate.
    @Test
    public void validate_arc_chain_passes_when_arc_seal_uses_1024_bit_key() throws Exception {
        assertValimailFixturePasses(
                valimailArcSealKeySizeMessage(
                        "1024",
                        "JZIhBQD/1SCIn7IUrIoqCDFZ4k2tDd5joLebC7dCEbEXy6HURnayDygFjEiVwoVjF8XZPo\n"
                        + "    tDSWEVj18YLFQ08HZigNNDmhAdtIAeHs5bTfhz3ZDKGISGSrVbUqvS5QaL2dwaY5V3FhH1QC\n"
                        + "    VEohhbx3rJKMBiFCbQoCRo555WNL0=",
                        "jCTMZoXkSSVEusJyP9cbvAoKEDLphi95R/yaX9+gWw2t/RduqINzxPSVJZUq8uVCbKdB5F\n"
                        + "    BlBb2m7zbwaq6/oemTqI1tcnRaAt66Z0cyOKfPjRINTm9C8E3hUoI9DzplkwEoqmhR0wOjcJ\n"
                        + "    H6ASJr96Kl5qLu092VFaQYYxkwh2I="),
                valimailKeySizeRecordRetriever);
    }

    // as_fields_b_2048: ARC-Seal signed with a 2048-bit RSA key must validate.
    @Test
    public void validate_arc_chain_passes_when_arc_seal_uses_2048_bit_key() throws Exception {
        assertValimailFixturePasses(
                valimailArcSealKeySizeMessage(
                        "2048",
                        "R6I8tV4Y0pBQWId+r4W9L3TDi82iVPot9d+ux5u69ET/VUTQUPFAiRfTBqMKAm0dY1HCdU\n"
                        + "    JZggmlvj9BwZMOO9pFi8O1EXqkJ1CpNtFyNn76Get96owYXh7LlcP/C/a5AmxZMmvKblloh5\n"
                        + "    1rL2cNWicsp8/y3NS8jO0KWpSis2jK2yMn+r9gJ5gM2sUiBsKDwiYAhFBhjD8SFQOaG6DzLa\n"
                        + "    mJzCw9FkuGdpLfQoNDq2lLQq6APq8GihFJai7o/s8M4FItAMoteuqxIfyYuH60oX4qNOsaIT\n"
                        + "    B/6DnRCFshABODpSHRRIH4EvCu2fYYo6YDIU3VvDH2wOO5fQMcgvUoNw==",
                        "M0YyrXMDoG5zJ0ZjFzUqFNoDFatu/QxWTjyAH5wPvPRiSqw2Vvd4A1Al8VjYfmgbP4Jd8f\n"
                        + "    TFDZg1kWwLYk2IO/th/P6iYPfyDg5qp6mgao/V8NBW9P/Mqlb+xhkn4R8c44vmen9atIUV3Z\n"
                        + "    04QzziVeuBxj+NFqxprbxf42Faxv5XymGmW3ZWVhOLEpwfcjy933drLsfZQezhyYlx4klptI\n"
                        + "    v3hKM76++GaIUc1nWXvmkeKKjEQLiUzqxd9Om7SRNArNe/q5xnVIaufxSfZNUtTT/o7Ic1Br\n"
                        + "    t7ZV8qwmj37sYpdZUo6H7QN+dp8E/J0jnbI0ZQU2mv8Gj3FqGOGzKwGQ=="),
                valimailKeySizeRecordRetriever);
    }

    // as_fields_b_512: ARC-Seal signed with a 512-bit RSA key must be rejected.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_uses_512_bit_key() throws Exception {
        assertValimailFixtureFails(
                valimailArcSealKeySizeMessage(
                        "512",
                        "DCbMvnfI7UzqahO9GFjYXa7DAcon0abOMQ7mWykqtdkEe+rqeQmsy1/pV9oAeSrT9giBqP\n"
                        + "    +cBNepG4Nycj93KQ==",
                        "BFnboE5xz5OBBIZeB04CaX0QVCRysZesZNKLQLDbq3ohfHL0eIkMWyt/ZkP3+bg7wVEtyb\n"
                        + "    QfqbbfDRTQYC3GBA=="),
                valimailKeySizeRecordRetriever);
    }

    // as_fields_b_head_case: ARC-Seal relaxed canonicalization lowercases header names.
    @Test
    public void validate_arc_chain_passes_when_arc_seal_header_name_case_changes() throws Exception {
        assertValimailFixturePasses(
                "MIME-Version: 1.0\n"
                + "Return-Path: <jqd@d1.example.org>\n"
                + "ARC-SEAL: a=rsa-sha256;\n"
                + "    b=RkKDOauVsqcsTEFv6NVE6J0sxj8LUE4kfwRzs0CvMg/+KOqRDQoFxxJsJkI77EHZqcSgwr\n"
                + "    QKpt6aKsl2zyUovVhAppT65S0+vo+h3utd3f8jph++1uiAUhVf57PihDC/GcdhyRGa6YNQGh\n"
                + "    GoArSHaJKb06/qF5OBif8o9lmRC8E=; cv=none; d=example.org; i=1; s=dummy;\n"
                + "    t=12345\n"
                + valimailArcSealFormatCommonTail());
    }

    // as_fields_b_head_unfold: folded ARC-Seal header lines must verify under relaxed canonicalization.
    @Test
    public void validate_arc_chain_passes_when_arc_seal_signature_header_is_unfolded() throws Exception {
        assertValimailFixturePasses(
                "MIME-Version: 1.0\n"
                + "Return-Path: <jqd@d1.example.org>\n"
                + "ARC-Seal: a=rsa-sha256;\n"
                + "    b=RkKDOauVsqcsTEFv6NVE6J0sxj8LUE4kfwRzs0CvMg/+KOqRDQoFxxJsJkI77EHZqcSgwr QKpt6aKsl2zyUovVhAppT65S0+vo+h3utd3f8jph++1uiAUhVf57PihDC/GcdhyRGa6YNQGh\n"
                + "    GoArSHaJKb06/qF5OBif8o9lmRC8E=; cv=none; d=example.org; i=1; s=dummy;\n"
                + "    t=12345\n"
                + valimailArcSealFormatCommonTail());
    }

    // as_fields_b_eol_wsp: trailing line whitespace must be stripped during AS verification.
    @Test
    public void validate_arc_chain_passes_when_arc_seal_signature_has_end_of_line_whitespace() throws Exception {
        assertValimailFixturePasses(
                "MIME-Version: 1.0\n"
                + "Return-Path: <jqd@d1.example.org>\n"
                + "ARC-Seal: a=rsa-sha256;\n"
                + "    b=RkKDOauVsqcsTEFv6NVE6J0sxj8LUE4kfwRzs0CvMg/+KOqRDQoFxxJsJkI77EHZqcSgwr    \n"
                + "    QKpt6aKsl2zyUovVhAppT65S0+vo+h3utd3f8jph++1uiAUhVf57PihDC/GcdhyRGa6YNQGh\n"
                + "    GoArSHaJKb06/qF5OBif8o9lmRC8E=; cv=none; d=example.org; i=1; s=dummy;\n"
                + "    t=12345\n"
                + valimailArcSealFormatCommonTail());
    }

    // as_fields_b_inl_wsp: repeated inline whitespace must be reduced during AS verification.
    @Test
    public void validate_arc_chain_passes_when_arc_seal_header_has_extra_inline_whitespace() throws Exception {
        assertValimailFixturePasses(
                "MIME-Version: 1.0\n"
                + "Return-Path: <jqd@d1.example.org>\n"
                + "ARC-Seal: a=rsa-sha256;\n"
                + "    b=RkKDOauVsqcsTEFv6NVE6J0sxj8LUE4kfwRzs0CvMg/+KOqRDQoFxxJsJkI77EHZqcSgwr\n"
                + "    QKpt6aKsl2zyUovVhAppT65S0+vo+h3utd3f8jph++1uiAUhVf57PihDC/GcdhyRGa6YNQGh\n"
                + "    GoArSHaJKb06/qF5OBif8o9lmRC8E=;    cv=none; d=example.org; i=1; s=dummy;\n"
                + "    t=12345\n"
                + valimailArcSealFormatCommonTail());
    }

    // as_fields_b_col_wsp: whitespace around the ARC-Seal field-name colon must be ignored.
    @Test
    public void validate_arc_chain_passes_when_arc_seal_header_has_whitespace_after_colon() throws Exception {
        assertValimailFixturePasses(
                "MIME-Version: 1.0\n"
                + "Return-Path: <jqd@d1.example.org>\n"
                + "ARC-Seal:   a=rsa-sha256;\n"
                + "    b=RkKDOauVsqcsTEFv6NVE6J0sxj8LUE4kfwRzs0CvMg/+KOqRDQoFxxJsJkI77EHZqcSgwr\n"
                + "    QKpt6aKsl2zyUovVhAppT65S0+vo+h3utd3f8jph++1uiAUhVf57PihDC/GcdhyRGa6YNQGh\n"
                + "    GoArSHaJKb06/qF5OBif8o9lmRC8E=; cv=none; d=example.org; i=1; s=dummy;\n"
                + "    t=12345\n"
                + valimailArcSealFormatCommonTail());
    }

    // as_fields_b_na: missing ARC-Seal b= leaves no signature to verify and must be rejected.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_signature_tag_is_missing() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replaceAll("; b=.*$", ""), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_fields_b_empty: empty ARC-Seal b= leaves no signature to verify and must be rejected.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_signature_tag_is_empty() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replaceAll("; b=.*$", "; b="), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_fields_b_base64: ARC-Seal b= must be base64.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_signature_is_not_base64() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replaceAll("; b=.*$", "; b=not-base64!"), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_fields_b_mod_sig: a modified ARC-Seal signature must be rejected.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_signature_is_modified() throws Exception {
        Message message = buildOneHopChainWithSeal(
                seal -> seal.replaceAll("; b=.*$", "; b=" + Base64.getEncoder().encodeToString(new byte[128])),
                true,
                false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_fields_b_aar1: modifying sealed AAR data must invalidate the ARC-Seal.
    @Test
    public void validate_arc_chain_fails_when_sealed_aar_data_is_modified() throws Exception {
        Message message = buildNHopChain(1);
        replaceTagOnHeader(message, ARC_AUTHENTICATION_RESULTS, "i=1", "dmarc=pass", "dmarc=fail");

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_fields_b_ams1: modifying sealed AMS data must invalidate the ARC-Seal.
    @Test
    public void validate_arc_chain_fails_when_sealed_ams_data_is_modified() throws Exception {
        Message message = buildNHopChain(1);
        replaceTagOnHeader(message, ARC_MESSAGE_SIGNATURE, "i=1", "h=subject : from : to", "h=from : to : subject");

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_fields_b_asb1: modifying sealed ARC-Seal data outside b= must invalidate the seal.
    @Test
    public void validate_arc_chain_fails_when_sealed_arc_seal_data_is_modified() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replace("t=1755918846", "t=1755918847"), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_fields_cv_na: missing ARC-Seal cv= must be rejected.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_cv_tag_is_missing() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replaceFirst("cv=none;\\s*", ""), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_fields_cv_empty: empty ARC-Seal cv= must be rejected.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_cv_tag_is_empty() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replace("cv=none", "cv="), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_fields_cv_invalid: invalid ARC-Seal cv= values must be rejected.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_cv_tag_is_invalid() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replace("cv=none", "cv=maybe"), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_fields_d_na: missing ARC-Seal d= prevents key lookup and must be rejected.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_domain_tag_is_missing() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replaceFirst("d=dmarc.example;\\s*", ""), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_fields_d_empty: empty ARC-Seal d= prevents key lookup and must be rejected.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_domain_tag_is_empty() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replace("d=dmarc.example", "d="), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_fields_d_invalid: invalid ARC-Seal d= values must be rejected.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_domain_tag_is_invalid() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replace("d=dmarc.example", "d=invalid_domain"), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_fields_h_present: ARC-Seal must not contain h=; it signs ARC set headers, not h=-listed headers.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_has_header_list_tag() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replace("t=1755918846", "h=subject; t=1755918846"), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_fields_s_na: missing ARC-Seal s= prevents key lookup and must be rejected.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_selector_tag_is_missing() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replaceFirst("s=arc;\\s*", ""), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_fields_s_empty: empty ARC-Seal s= prevents key lookup and must be rejected.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_selector_tag_is_empty() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replace("s=arc", "s="), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_fields_t_na: ARC-Seal t= is optional and a seal generated without it must validate.
    @Test
    public void validate_arc_chain_passes_when_arc_seal_timestamp_tag_is_missing() throws Exception {
        String sealTemplateWithoutTimestamp = "i=; cv=; a=rsa-sha256; d=dmarc.example; s=arc; b=";
        Message message = buildOneHopChainWithSealTemplate(sealTemplateWithoutTimestamp);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("pass");
    }

    // as_fields_t_empty: empty ARC-Seal t= must be rejected.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_timestamp_tag_is_empty() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replace("t=1755918846", "t="), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // as_fields_t_invalid: invalid ARC-Seal t= values must be rejected.
    @Test
    public void validate_arc_chain_fails_when_arc_seal_timestamp_tag_is_invalid() throws Exception {
        Message message = buildOneHopChainWithSeal(seal -> seal.replace("t=1755918846", "t=abc"), true, false);

        ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    // Builds a valid two-hop ARC chain: applies i=1 to the base message, then applies i=2 on top.
    private Message buildTwoHopChain() throws Exception {
        return buildNHopChain(2);
    }

    private Message buildOneHopChainWithSealTemplate(String sealTemplate) throws Exception {
        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        Message message = new DefaultMessageBuilder().parseMessage(emailStream);
        ArcSetBuilder builder = new ArcSetBuilder(
                ArcTestKeys.privateKeyArc,
                ARC_AMS_TEMPLATE,
                sealTemplate,
                AUTH_SERVICE,
                TIMESTAMP);
        Map<String, String> arcSet = builder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);
        for (Map.Entry<String, String> entry : arcSet.entrySet()) {
            message.getHeader().addField(new RawField(entry.getKey(), entry.getValue()));
        }
        return message;
    }

    private Message buildOneHopChainWithSeal(java.util.function.Function<String, String> sealMutation,
                                             boolean includeSeal,
                                             boolean duplicateSeal) throws Exception {
        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        Message message = new DefaultMessageBuilder().parseMessage(emailStream);
        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);

        message.getHeader().addField(new RawField(ARC_AUTHENTICATION_RESULTS, arcSet.get(ARC_AUTHENTICATION_RESULTS)));
        message.getHeader().addField(new RawField(ARC_MESSAGE_SIGNATURE, arcSet.get(ARC_MESSAGE_SIGNATURE)));
        if (includeSeal) {
            String seal = sealMutation.apply(arcSet.get(ARC_SEAL));
            message.getHeader().addField(new RawField(ARC_SEAL, seal));
            if (duplicateSeal) {
                message.getHeader().addField(new RawField(ARC_SEAL, seal));
            }
        }
        return message;
    }

    private Message buildOneHopChainWithAms(java.util.function.Function<String, String> amsMutation,
                                            boolean duplicateAms) throws Exception {
        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        Message message = new DefaultMessageBuilder().parseMessage(emailStream);
        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);

        message.getHeader().addField(new RawField(ARC_AUTHENTICATION_RESULTS, arcSet.get(ARC_AUTHENTICATION_RESULTS)));
        String ams = amsMutation.apply(arcSet.get(ARC_MESSAGE_SIGNATURE));
        message.getHeader().addField(new RawField(ARC_MESSAGE_SIGNATURE, ams));
        if (duplicateAms) {
            message.getHeader().addField(new RawField(ARC_MESSAGE_SIGNATURE, ams));
        }
        message.getHeader().addField(new RawField(ARC_SEAL, arcSet.get(ARC_SEAL)));
        return message;
    }

    private String insertWhitespaceIntoSealSignature(String seal) {
        java.util.regex.Matcher matcher = java.util.regex.Pattern.compile("; b=([^;]+)$").matcher(seal);
        if (!matcher.find()) {
            throw new AssertionError("ARC-Seal b= not found");
        }
        String signature = matcher.group(1);
        String spacedSignature = signature.substring(0, 24) + " \r\n\t" + signature.substring(24, 64)
                + "  " + signature.substring(64);
        return matcher.replaceFirst("; b=" + spacedSignature);
    }

    private Message buildOneHopChainWithAar(String aarOverride, boolean includeAar, boolean duplicateAar) throws Exception {
        ByteArrayInputStream emailStream = readFileToByteArrayInputStream("/mail/rfc8617_no_arc.eml");
        Message message = new DefaultMessageBuilder().parseMessage(emailStream);
        Map<String, String> arcSet = arcSetBuilder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);

        if (includeAar) {
            String aar = aarOverride == null ? arcSet.get(ARC_AUTHENTICATION_RESULTS) : aarOverride;
            message.getHeader().addField(new RawField(ARC_AUTHENTICATION_RESULTS, aar));
            if (duplicateAar) {
                message.getHeader().addField(new RawField(ARC_AUTHENTICATION_RESULTS, aar));
            }
        }
        message.getHeader().addField(new RawField(ARC_MESSAGE_SIGNATURE, arcSet.get(ARC_MESSAGE_SIGNATURE)));
        message.getHeader().addField(new RawField(ARC_SEAL, arcSet.get(ARC_SEAL)));
        return message;
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

    private void assertValimailFixturePasses(String rawMessage) throws Exception {
        assertValimailFixturePasses(rawMessage, valimailKeyRecordRetriever);
    }

    private void assertValimailFixturePasses(String rawMessage, MockPublicKeyRecordRetrieverArc publicKeyRetriever) throws Exception {
        Message message = new DefaultMessageBuilder().parseMessage(
                new ByteArrayInputStream(rawMessage.replace("\n", "\r\n").getBytes(StandardCharsets.UTF_8)));
        ARCChainValidator arcChainValidator = new ARCChainValidator(publicKeyRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("pass");
    }

    private void assertValimailFixtureFails(String rawMessage, MockPublicKeyRecordRetrieverArc publicKeyRetriever) throws Exception {
        Message message = new DefaultMessageBuilder().parseMessage(
                new ByteArrayInputStream(rawMessage.replace("\n", "\r\n").getBytes(StandardCharsets.UTF_8)));
        ARCChainValidator arcChainValidator = new ARCChainValidator(publicKeyRetriever);
        ArcValidationOutcome cv = arcChainValidator.validateArcChain(message);
        assertThat(cv.getResult().toString().toLowerCase()).isEqualTo("fail");
    }

    private void assertValimailFixtureFails(String rawMessage) throws Exception {
        assertValimailFixtureFails(rawMessage, valimailKeyRecordRetriever);
    }

    private Map<String, String> buildArcSetWithAuthService(Message message, String authService) throws Exception {
        ArcSetBuilder builder = new ArcSetBuilder(
                ArcTestKeys.privateKeyArc,
                ARC_AMS_TEMPLATE,
                ARC_SEAL_TEMPLATE,
                authService,
                TIMESTAMP);
        return builder.buildArcSet(message, HELO, MAIL_FROM, IP, keyRecordRetriever);
    }

    private Message parseRawEmail(String rawMessage) throws Exception {
        return new DefaultMessageBuilder().parseMessage(
                new ByteArrayInputStream(rawMessage.replace("\n", "\r\n").getBytes(StandardCharsets.UTF_8)));
    }

    private String basicMessageWithoutAuthenticationResults() {
        return "MIME-Version: 1.0\n"
                + "Return-Path: <jqd@d1.example.org>\n"
                + "Received: by 10.157.14.6 with HTTP; Tue, 3 Jan 2017 12:22:54 -0800 (PST)\n"
                + "Message-ID: <54B84785.1060301@d1.example.org>\n"
                + "Date: Thu, 14 Jan 2015 15:00:01 -0800\n"
                + "From: John Q Doe <jqd@d1.example.org>\n"
                + "To: arc@dmarc.org\n"
                + "Subject: Example 1\n"
                + "\n"
                + "Hey gang,\n"
                + "This is a test message.\n"
                + "--J.";
    }

    private String valimailCommonMessageTail() {
        return "ARC-Authentication-Results: i=1; lists.example.org;\n"
                + "    spf=pass smtp.mfrom=jqd@d1.example;\n"
                + "    dkim=pass (1024-bit key) header.i=@d1.example;\n"
                + "    dmarc=pass\n"
                + "Received: from segv.d1.example (segv.d1.example [72.52.75.15])\n"
                + "    by lists.example.org (8.14.5/8.14.5) with ESMTP id t0EKaNU9010123\n"
                + "    for <arc@example.org>; Thu, 14 Jan 2015 15:01:30 -0800 (PST)\n"
                + "    (envelope-from jqd@d1.example)\n"
                + "Authentication-Results: lists.example.org;\n"
                + "    spf=pass smtp.mfrom=jqd@d1.example;\n"
                + "    dkim=pass (1024-bit key) header.i=@d1.example;\n"
                + "    dmarc=pass\n"
                + "Received: by 10.157.14.6 with HTTP; Tue, 3 Jan 2017 12:22:54 -0800 (PST)\n"
                + "Message-ID: <54B84785.1060301@d1.example.org>\n"
                + "Date: Thu, 14 Jan 2015 15:00:01 -0800\n"
                + "From: John Q Doe <jqd@d1.example.org>\n"
                + "To: arc@dmarc.org\n"
                + "Subject: Example 1\n"
                + "\n"
                + "Hey gang,\n"
                + "This is a test message.\n"
                + "--J.";
    }

    private String valimailAmsCanonicalizationMessage(String signedMessageTail) {
        return "MIME-Version: 1.0\n"
                + "Return-Path: <jqd@d1.example.org>\n"
                + "ARC-Seal: a=rsa-sha256;\n"
                + "    b=dOdFEyhrk/tw5wl3vMIogoxhaVsKJkrkEhnAcq2XqOLSQhPpGzhGBJzR7k1sWGokon3TmQ\n"
                + "    7TX9zQLO6ikRpwd/pUswiRW5DBupy58fefuclXJAhErsrebfvfiueGyhHXV7C1LyJTztywzn\n"
                + "    QGG4SCciU/FTlsJ0QANrnLRoadfps=; cv=none; d=example.org; i=1; s=dummy;\n"
                + "    t=12345\n"
                + "ARC-Message-Signature: a=rsa-sha256;\n"
                + "    b=QsRzR/UqwRfVLBc1TnoQomlVw5qi6jp08q8lHpBSl4RehWyHQtY3uOIAGdghDk/mO+/Xpm\n"
                + "    9JA5UVrPyDV0f+2q/YAHuwvP11iCkBQkocmFvgTSxN8H+DwFFPrVVUudQYZV7UDDycXoM6UE\n"
                + "    cdfzLLzVNPOAHEDIi/uzoV4sUqZ18=;\n"
                + "    bh=KWSe46TZKCcDbH4klJPo+tjk5LWJnVRlP5pvjXFZYLQ=; c=relaxed/relaxed;\n"
                + "    d=example.org; h=from:to:date:subject:mime-version:arc-authentication-results;\n"
                + "    i=1; s=dummy; t=12345\n"
                + "ARC-Authentication-Results: i=1; lists.example.org;\n"
                + "    spf=pass smtp.mfrom=jqd@d1.example;\n"
                + "    dkim=pass (1024-bit key) header.i=@d1.example;\n"
                + "    dmarc=pass\n"
                + signedMessageTail;
    }

    private String valimailArcSealFormatCommonTail() {
        return "ARC-Message-Signature: a=rsa-sha256;\n"
                + "    b=SMBCg/tHQkIAIzx7OFir0bMhCxk/zaMOx1nyOSAviXW88ERohOFOXIkBVGe74xfJDSh9ou\n"
                + "    ryKgNA4XhUt4EybBXOn1dlrMA07dDIUFOUE7n+8QsvX1Drii8aBIpiu+O894oBEDSYcd1R+z\n"
                + "    sZIdXhOjB/Lt4sTE1h5IT2p3UctgY=;\n"
                + "    bh=dHN66dCNljBC18wb03I1K6hlBvV0qqsKoDsetl+jxb8=; c=relaxed/relaxed;\n"
                + "    d=example.org; h=from:to:date:subject:mime-version:arc-authentication-results;\n"
                + "    i=1; s=dummy; t=12345\n"
                + "ARC-Authentication-Results: i=1; lists.example.org;\n"
                + "    spf=pass smtp.mfrom=jqd@d1.example;\n"
                + "    dkim=pass (1024-bit key) header.i=@d1.example;\n"
                + "    dmarc=pass\n"
                + "Received: from segv.d1.example (segv.d1.example [72.52.75.15])\n"
                + "    by lists.example.org (8.14.5/8.14.5) with ESMTP id t0EKaNU9010123\n"
                + "    for <arc@example.org>; Thu, 14 Jan 2015 15:01:30 -0800 (PST)\n"
                + "    (envelope-from jqd@d1.example)\n"
                + "Authentication-Results: lists.example.org;\n"
                + "    spf=pass smtp.mfrom=jqd@d1.example;\n"
                + "    dkim=pass (1024-bit key) header.i=@d1.example;\n"
                + "    dmarc=pass\n"
                + "MIME-Version: 1.0\n"
                + "Return-Path: <jqd@d1.example.org>\n"
                + "Received: by 10.157.52.162 with SMTP id g31csp5274520otc;\n"
                + "        Tue, 3 Jan 2017 12:32:02 -0800 (PST)\n"
                + "X-Received: by 10.36.31.84 with SMTP id d81mr49584685itd.26.1483475522271;\n"
                + "        Tue, 03 Jan 2017 12:32:02 -0800 (PST)\n"
                + "Message-ID: <C3A9E208-6B5D-4D9F-B4DE-9323946993AC@d1.example.org>\n"
                + "Date: Thu, 5 Jan 2017 14:39:01 -0800\n"
                + "From: Gene Q Doe <gqd@d1.example.org>\n"
                + "To: arc@dmarc.org\n"
                + "Subject: Example 2\n"
                + "Content-Type: multipart/alternative; boundary=001a113e15fcdd0f9e0545366e8f\n"
                + "\n"
                + "--001a113e15fcdd0f9e0545366e8f\n"
                + "Content-Type: text/plain; charset=UTF-8\n"
                + "\n"
                + "This is a test message\n"
                + "\n"
                + "--001a113e15fcdd0f9e0545366e8f\n"
                + "Content-Type: text/html; charset=UTF-8\n"
                + "\n"
                + "<div dir=\"ltr\">This is a test message</div>\n"
                + "\n"
                + "--001a113e15fcdd0f9e0545366e8f--";
    }

    private String valimailArcSealKeySizeMessage(String selector, String arcSealSignature, String arcMessageSignature) {
        return "MIME-Version: 1.0\n"
                + "Return-Path: <jqd@d1.example.org>\n"
                + "ARC-Seal: a=rsa-sha256;\n"
                + "    b=" + arcSealSignature + "; cv=none; d=example.org; i=1; s=" + selector + ";\n"
                + "    t=12345\n"
                + "ARC-Message-Signature: a=rsa-sha256;\n"
                + "    b=" + arcMessageSignature + ";\n"
                + "    bh=dHN66dCNljBC18wb03I1K6hlBvV0qqsKoDsetl+jxb8=; c=relaxed/relaxed;\n"
                + "    d=example.org; h=from:to:date:subject:mime-version:arc-authentication-results;\n"
                + "    i=1; s=" + selector + "; t=12345\n"
                + "ARC-Authentication-Results: i=1; lists.example.org;\n"
                + "    spf=pass smtp.mfrom=jqd@d1.example;\n"
                + "    dkim=pass (1024-bit key) header.i=@d1.example;\n"
                + "    dmarc=pass\n"
                + "Received: from segv.d1.example (segv.d1.example [72.52.75.15])\n"
                + "    by lists.example.org (8.14.5/8.14.5) with ESMTP id t0EKaNU9010123\n"
                + "    for <arc@example.org>; Thu, 14 Jan 2015 15:01:30 -0800 (PST)\n"
                + "    (envelope-from jqd@d1.example)\n"
                + "Authentication-Results: lists.example.org;\n"
                + "    spf=pass smtp.mfrom=jqd@d1.example;\n"
                + "    dkim=pass (1024-bit key) header.i=@d1.example;\n"
                + "    dmarc=pass\n"
                + "MIME-Version: 1.0\n"
                + "Return-Path: <jqd@d1.example.org>\n"
                + "Received: by 10.157.52.162 with SMTP id g31csp5274520otc;\n"
                + "        Tue, 3 Jan 2017 12:32:02 -0800 (PST)\n"
                + "X-Received: by 10.36.31.84 with SMTP id d81mr49584685itd.26.1483475522271;\n"
                + "        Tue, 03 Jan 2017 12:32:02 -0800 (PST)\n"
                + "Message-ID: <C3A9E208-6B5D-4D9F-B4DE-9323946993AC@d1.example.org>\n"
                + "Date: Thu, 5 Jan 2017 14:39:01 -0800\n"
                + "From: Gene Q Doe <gqd@d1.example.org>\n"
                + "To: arc@dmarc.org\n"
                + "Subject: Example 2\n"
                + "Content-Type: multipart/alternative; boundary=001a113e15fcdd0f9e0545366e8f\n"
                + "\n"
                + "--001a113e15fcdd0f9e0545366e8f\n"
                + "Content-Type: text/plain; charset=UTF-8\n"
                + "\n"
                + "This is a test message\n"
                + "\n"
                + "--001a113e15fcdd0f9e0545366e8f\n"
                + "Content-Type: text/html; charset=UTF-8\n"
                + "\n"
                + "<div dir=\"ltr\">This is a test message</div>\n"
                + "\n"
                + "--001a113e15fcdd0f9e0545366e8f--";
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
