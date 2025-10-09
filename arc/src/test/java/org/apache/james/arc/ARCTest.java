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

import org.apache.commons.codec.binary.Base64;
import org.apache.james.jdkim.DKIMCommon;
import org.apache.james.jdkim.MockPublicKeyRecordRetriever;
import org.apache.james.mime4j.dom.Message;
import org.apache.james.mime4j.message.DefaultMessageBuilder;
import org.apache.james.mime4j.stream.RawField;
import org.junit.Test;

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

    private final MockPublicKeyRecordRetrieverArc keyRecordRetriever = new MockPublicKeyRecordRetrieverArc(
            MockPublicKeyRecordRetriever.Record.of(
                    "arc",
                    "dmarc.example",
                    "k=rsa; p=" + Base64.encodeBase64String(ArcTestKeys.publicKeyArc.getEncoded()) + ";"
            ),
            MockPublicKeyRecordRetriever.Record.of(
                    "origin2015",
                    "d1.example",
                    "k=rsa; p=" + Base64.encodeBase64String(ArcTestKeys.publicKeyDkim.getEncoded()) + ";"
            ),
            MockPublicKeyRecordRetrieverArc.DmarcRecord.dmarcOf("",
                    "d1.example",
                    "k=rsa; v=DMARC1; p=reject; pct=100; rua=mailto:noc@d1.example"
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

    private static final String DMARC_RESPONSE_TEMPLATE = "dmarc=%s (p=%s) header.from=%s";
    private static final String DMARC_NON_RESPONSE_TEMPLATE = "dmarc=none (no policy) header.from=";

    ArcSetBuilder arcSetBuilder = new ArcSetBuilder(ArcTestKeys.privateKeyArc, ARC_AMS_TEMPLATE, ARC_SEAL_TEMPLATE, DMARC_RESPONSE_TEMPLATE, DMARC_NON_RESPONSE_TEMPLATE, AUTH_SERVICE, TIMESTAMP);

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
        String cv = arcChainValidator.validateArcChain(message).name().toLowerCase();
        assertThat(cv).isEqualTo(expectedCv);

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