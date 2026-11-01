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

import static org.assertj.core.api.Assertions.assertThatCode;
import org.apache.james.jdkim.impl.Message;
import java.util.Base64;
import java.security.Signature;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.james.jdkim.api.PublicKeyRecord;
import org.apache.james.jdkim.api.PublicKeyRecordRetriever;
import org.apache.james.jdkim.api.Result;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.api.VerifierOptions;
import org.apache.james.jdkim.exceptions.FailException;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.exceptions.TempFailException;
import org.apache.james.jdkim.tagvalue.PublicKeyRecordImpl;
import org.apache.james.jdkim.tagvalue.SignatureRecordImpl;
import static org.junit.Assert.fail;
import org.junit.Test;

public class DKIMVerifierTest {

    @Test
    public void testApply() throws PermFailException {
        PublicKeyRecord pkr = new PublicKeyRecordImpl(
                "k=rsa; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIhyR3oItOy22ZOaBrIVe9m/iME3RqOJeasANSpg2YTHTYV+Xtp4xwf5gTjCmHQEMOs0qYu0FYiNQPQogJ2t0Mfx9zNu06rfRBDjiIU9tpx2T+NGlWZ8qhbiLo5By8apJavLyqTLavyPSrvsx0B3YzC63T4Age2CDqZYA+OwSMWQIDAQAB");
        pkr.validate();
        DKIMVerifier
                .apply(
                        pkr,
                        new SignatureRecordImpl(
                                "v=1; a=rsa-sha256; c=relaxed/relaxed; d=gmail.com; s=gamma; h=domainkey-signature:mime-version:received:date:message-id:subject:from:to:content-type; bh=AbPsrGRdyVjM2e5ZZdhQA/aLe305f2bPvPRohUxrGjo=; b=ksNsfQJv20M9/Vf66sMJT1WHM/fUfcqli1NfkyxSOjr8jlNTH4JNCGacb2neWuwMN4C4TFXqMR8BENkn+XrCV1FjrlW1mCxlLDilVypP/uqqq04KzJpVyJG6zZLd/0DeknSLN6sDGKdCvIdS+YpHEhUxoEuf6QizCs8PTXhnJiA="));
        try {
            DKIMVerifier
                    .apply(
                            pkr,
                            new SignatureRecordImpl(
                                    "v=1; a=dsa-sha256; c=relaxed/relaxed; d=gmail.com; s=gamma; h=domainkey-signature:mime-version:received:date:message-id:subject:from:to:content-type; bh=AbPsrGRdyVjM2e5ZZdhQA/aLe305f2bPvPRohUxrGjo=; b=ksNsfQJv20M9/Vf66sMJT1WHM/fUfcqli1NfkyxSOjr8jlNTH4JNCGacb2neWuwMN4C4TFXqMR8BENkn+XrCV1FjrlW1mCxlLDilVypP/uqqq04KzJpVyJG6zZLd/0DeknSLN6sDGKdCvIdS+YpHEhUxoEuf6QizCs8PTXhnJiA="));
            fail("This is not a signature for that key");
        } catch (PermFailException | IllegalStateException e) {
        }
        pkr = new PublicKeyRecordImpl(
                "k=rsa; t=y:s; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIhyR3oItOy22ZOaBrIVe9m/iME3RqOJeasANSpg2YTHTYV+Xtp4xwf5gTjCmHQEMOs0qYu0FYiNQPQogJ2t0Mfx9zNu06rfRBDjiIU9tpx2T+NGlWZ8qhbiLo5By8apJavLyqTLavyPSrvsx0B3YzC63T4Age2CDqZYA+OwSMWQIDAQAB");
        pkr.validate();
        DKIMVerifier
                .apply(
                        pkr,
                        new SignatureRecordImpl(
                                "v=1; a=rsa-sha256; c=relaxed/relaxed; i=test@gmail.com; d=gmail.com; s=gamma; h=domainkey-signature:mime-version:received:date:message-id:subject:from:to:content-type; bh=AbPsrGRdyVjM2e5ZZdhQA/aLe305f2bPvPRohUxrGjo=; b=ksNsfQJv20M9/Vf66sMJT1WHM/fUfcqli1NfkyxSOjr8jlNTH4JNCGacb2neWuwMN4C4TFXqMR8BENkn+XrCV1FjrlW1mCxlLDilVypP/uqqq04KzJpVyJG6zZLd/0DeknSLN6sDGKdCvIdS+YpHEhUxoEuf6QizCs8PTXhnJiA="));
        try {
            DKIMVerifier
                    .apply(
                            pkr,
                            new SignatureRecordImpl(
                                    "v=1; a=rsa-sha256; c=relaxed/relaxed; i=test@subdomain.gmail.com; d=gmail.com; s=gamma; h=domainkey-signature:mime-version:received:date:message-id:subject:from:to:content-type; bh=AbPsrGRdyVjM2e5ZZdhQA/aLe305f2bPvPRohUxrGjo=; b=ksNsfQJv20M9/Vf66sMJT1WHM/fUfcqli1NfkyxSOjr8jlNTH4JNCGacb2neWuwMN4C4TFXqMR8BENkn+XrCV1FjrlW1mCxlLDilVypP/uqqq04KzJpVyJG6zZLd/0DeknSLN6sDGKdCvIdS+YpHEhUxoEuf6QizCs8PTXhnJiA="));
            fail("This is not a signature for that key");
        } catch (PermFailException e) {
        }
        pkr = new PublicKeyRecordImpl(
                "k=rsa; g=test*; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIhyR3oItOy22ZOaBrIVe9m/iME3RqOJeasANSpg2YTHTYV+Xtp4xwf5gTjCmHQEMOs0qYu0FYiNQPQogJ2t0Mfx9zNu06rfRBDjiIU9tpx2T+NGlWZ8qhbiLo5By8apJavLyqTLavyPSrvsx0B3YzC63T4Age2CDqZYA+OwSMWQIDAQAB");
        pkr.validate();
        DKIMVerifier
                .apply(
                        pkr,
                        new SignatureRecordImpl(
                                "v=1; a=rsa-sha256; c=relaxed/relaxed; i=test@gmail.com; d=gmail.com; s=gamma; h=domainkey-signature:mime-version:received:date:message-id:subject:from:to:content-type; bh=AbPsrGRdyVjM2e5ZZdhQA/aLe305f2bPvPRohUxrGjo=; b=ksNsfQJv20M9/Vf66sMJT1WHM/fUfcqli1NfkyxSOjr8jlNTH4JNCGacb2neWuwMN4C4TFXqMR8BENkn+XrCV1FjrlW1mCxlLDilVypP/uqqq04KzJpVyJG6zZLd/0DeknSLN6sDGKdCvIdS+YpHEhUxoEuf6QizCs8PTXhnJiA="));
        try {
            DKIMVerifier
                    .apply(
                            pkr,
                            new SignatureRecordImpl(
                                    "v=1; a=rsa-sha256; c=relaxed/relaxed; i=bad@subdomain.gmail.com; d=gmail.com; s=gamma; h=domainkey-signature:mime-version:received:date:message-id:subject:from:to:content-type; bh=AbPsrGRdyVjM2e5ZZdhQA/aLe305f2bPvPRohUxrGjo=; b=ksNsfQJv20M9/Vf66sMJT1WHM/fUfcqli1NfkyxSOjr8jlNTH4JNCGacb2neWuwMN4C4TFXqMR8BENkn+XrCV1FjrlW1mCxlLDilVypP/uqqq04KzJpVyJG6zZLd/0DeknSLN6sDGKdCvIdS+YpHEhUxoEuf6QizCs8PTXhnJiA="));
            fail("This is not a signature for that key");
        } catch (PermFailException e) {
        }
        pkr = new PublicKeyRecordImpl(
                "k=rsa; g=test*; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIhyR3oItOy22ZOaBrIVe9m/iME3RqOJeasANSpg2YTHTYV+Xtp4xwf5gTjCmHQEMOs0qYu0FYiNQPQogJ2t0Mfx9zNu06rfRBDjiIU9tpx2T+NGlWZ8qhbiLo5By8apJavLyqTLavyPSrvsx0B3YzC63T4Age2CDqZYA+OwSMWQIDAQAB");
        pkr.validate();

        pkr = new PublicKeyRecordImpl(
                "k=rsa; h=sha1; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIhyR3oItOy22ZOaBrIVe9m/iME3RqOJeasANSpg2YTHTYV+Xtp4xwf5gTjCmHQEMOs0qYu0FYiNQPQogJ2t0Mfx9zNu06rfRBDjiIU9tpx2T+NGlWZ8qhbiLo5By8apJavLyqTLavyPSrvsx0B3YzC63T4Age2CDqZYA+OwSMWQIDAQAB");
        pkr.validate();
        try {
            DKIMVerifier
                    .apply(
                            pkr,
                            new SignatureRecordImpl(
                                    "v=1; a=rsa-sha256; c=relaxed/relaxed; d=gmail.com; s=gamma; h=domainkey-signature:mime-version:received:date:message-id:subject:from:to:content-type; bh=AbPsrGRdyVjM2e5ZZdhQA/aLe305f2bPvPRohUxrGjo=; b=ksNsfQJv20M9/Vf66sMJT1WHM/fUfcqli1NfkyxSOjr8jlNTH4JNCGacb2neWuwMN4C4TFXqMR8BENkn+XrCV1FjrlW1mCxlLDilVypP/uqqq04KzJpVyJG6zZLd/0DeknSLN6sDGKdCvIdS+YpHEhUxoEuf6QizCs8PTXhnJiA="));
            fail("This hash method is not supported for that publick key");
        } catch (PermFailException e) {
        }
    }

    @Test
    public void repeatedLookupMethodsShouldBeQueriedOnce() {
        AtomicInteger calls = new AtomicInteger();
        DKIMVerifier verifier = new DKIMVerifier((method, selector, token) -> {
            calls.incrementAndGet();
            throw new TempFailException("SERVFAIL");
        });
        SignatureRecord sign = verifier.newSignatureRecord(
                "v=1; a=rsa-sha256; d=example.com; s=s0; h=from; bh=AAAA; b=AAAA; q=" + String.join(":", Collections.nCopies(100, "dns/txt")));

        assertThatThrownBy(() -> verifier.publicRecordLookup(sign)).isInstanceOf(TempFailException.class);
        assertThat(calls.get()).isEqualTo(1);
    }

    @Test
    public void verifierShouldBoundTheNumberOfSignaturesItVerifies() {
        AtomicInteger calls = new AtomicInteger();
        PublicKeyRecordRetriever retriever = (method, selector, token) -> {
            calls.incrementAndGet();
            throw new PermFailException("no key");
        };
        StringBuilder mail = new StringBuilder();
        for (int i = 0; i < 200; i++) {
            mail.append("DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=s").append(i).append("; h=from; bh=AAAA; b=AAAA\r\n");
        }
        mail.append("From: joe@example.com\r\n\r\nbody\r\n");
        DKIMVerifier verifier = new DKIMVerifier(new VerifierOptions.Builder()
                .withPublicKeyRecordRetriever(retriever).withMaxSignatures(10).build());

        assertThatThrownBy(() -> verifier.verify(new ByteArrayInputStream(mail.toString().getBytes(StandardCharsets.US_ASCII))))
                .isInstanceOf(FailException.class);
        assertThat(calls.get()).isEqualTo(10);
        assertThat(verifier.getResults()).hasSize(200);
        assertThat(verifier.getResults()).allMatch(r -> r.getResultType() == Result.Type.PERMERROR);
        assertThat(verifier.getResults().stream().filter(r -> r.getErrorMessage().startsWith("Too many DKIM-Signature fields"))).hasSize(190);
    }

    @Test
    public void verifyShouldFailWithPermFailOnUndecodableBodyHash() throws Exception {
        String tags = " b=; v=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=ab=c";
        String headers = "From: joe@example.com\r\n";
        SignatureRecordImpl record = new SignatureRecordImpl(tags);
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(TestKeys.privateKey);
        DKIMCommon.signatureCheck(new Message(new ByteArrayInputStream((headers + "\r\n").getBytes(StandardCharsets.US_ASCII))),
                record, record.getHeaders(), signer);
        String b = Base64.getEncoder().encodeToString(signer.sign());
        String mail = "DKIM-Signature:" + tags.replace("b=;", "b=" + b + ";") + "\r\n" + headers + "\r\nbody\r\n";

        DKIMVerifier verifier = new DKIMVerifier(new MockPublicKeyRecordRetriever(
                "v=DKIM1; k=rsa; p=" + Base64.getEncoder().encodeToString(TestKeys.publicKey.getEncoded()), "sel", "example.com"));

        assertThatThrownBy(() -> verifier.verify(new ByteArrayInputStream(mail.getBytes(StandardCharsets.US_ASCII))))
                .isInstanceOf(PermFailException.class);
        assertThat(verifier.hasAnyValidSignature()).isFalse();
        assertThat(verifier.getResults()).hasSize(1);
    }

    @Test
    public void defaultGranularityShouldMatchAnyLocalPart() throws Exception {
        PublicKeyRecordImpl key = new PublicKeyRecordImpl("v=DKIM1; k=rsa; p=AAAA");
        SignatureRecordImpl sign = new SignatureRecordImpl(
                "v=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=AA==; b=AA==; i==C3=85sa@example.com");

        assertThatCode(() -> DKIMVerifier.apply(key, sign)).doesNotThrowAnyException();
    }

    @Test
    public void granularityWildcardShouldMatchLineTerminators() throws Exception {
        PublicKeyRecordImpl key = new PublicKeyRecordImpl("v=DKIM1; k=rsa; g=a*b; p=AAAA");

        assertThat(key.getGranularityPattern().matcher("a\r\nb").matches()).isTrue();
        assertThat(key.getGranularityPattern().matcher("ab\n").matches()).isFalse();
    }

    private static DKIMVerifier signAndVerify(int keyBits, VerifierOptions.Builder options, StringBuilder mailOut) throws Exception {
        return signAndVerify(keyBits, "rsa-sha256", options, mailOut, new AtomicInteger());
    }

    private static DKIMVerifier signAndVerify(int keyBits, String algorithm, VerifierOptions.Builder options, StringBuilder mailOut,
                                              AtomicInteger lookups) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(keyBits);
        KeyPair pair = gen.generateKeyPair();
        MockPublicKeyRecordRetriever records = new MockPublicKeyRecordRetriever();
        records.addRecord("sel", "example.com",
                "v=DKIM1; p=" + Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        PublicKeyRecordRetriever retriever = (method, selector, token) -> {
            lookups.incrementAndGet();
            return records.getRecords(method, selector, token);
        };
        String message = "From: joe@example.com\r\nSubject: test\r\n\r\nbody\r\n";
        String field = new DKIMSigner("v=1; a=" + algorithm + "; d=example.com; s=sel; h=from:subject; bh=; b=;", pair.getPrivate())
                .sign(new ByteArrayInputStream(message.getBytes(StandardCharsets.US_ASCII)));
        mailOut.append(field).append("\r\n").append(message);
        return new DKIMVerifier(options.withPublicKeyRecordRetriever(retriever).build());
    }

    @Test
    public void shortRsaKeysShouldNotPass() throws Exception {
        for (int bits : new int[] {512, 768}) {
            StringBuilder mail = new StringBuilder();
            DKIMVerifier verifier = signAndVerify(bits, new VerifierOptions.Builder(), mail);

            assertThatThrownBy(() -> verifier.verify(new ByteArrayInputStream(mail.toString().getBytes(StandardCharsets.US_ASCII))))
                    .isInstanceOf(PermFailException.class)
                    .hasMessageContaining("RSA key too short: " + bits + " bits");
            assertThat(verifier.getResults()).extracting(Result::getResultType).containsExactly(Result.Type.PERMERROR);
        }
    }

    @Test
    public void shortRsaKeysShouldPassWhenAllowed() throws Exception {
        StringBuilder mail = new StringBuilder();
        DKIMVerifier verifier = signAndVerify(512, new VerifierOptions.Builder().withMinimumRsaKeyBits(512), mail);

        assertThat(verifier.verify(new ByteArrayInputStream(mail.toString().getBytes(StandardCharsets.US_ASCII)))).hasSize(1);
    }

    @Test
    public void rsaKeysOfTheMinimumLengthShouldPass() throws Exception {
        StringBuilder mail = new StringBuilder();
        DKIMVerifier verifier = signAndVerify(1024, new VerifierOptions.Builder(), mail);

        assertThat(verifier.verify(new ByteArrayInputStream(mail.toString().getBytes(StandardCharsets.US_ASCII)))).hasSize(1);
    }

    @Test
    public void rsaSha1ShouldBeRefusedWhenDisallowed() throws Exception {
        StringBuilder mail = new StringBuilder();
        AtomicInteger lookups = new AtomicInteger();
        DKIMVerifier verifier = signAndVerify(2048, "rsa-sha1", new VerifierOptions.Builder().withRsaSha1Allowed(false), mail, lookups);

        assertThatThrownBy(() -> verifier.verify(new ByteArrayInputStream(mail.toString().getBytes(StandardCharsets.US_ASCII))))
                .isInstanceOf(PermFailException.class)
                .hasMessageContaining("rsa-sha1 is not accepted");
        assertThat(verifier.getResults()).extracting(Result::getResultType).containsExactly(Result.Type.PERMERROR);
        assertThat(lookups.get()).isZero();
    }

    @Test
    public void rsaSha1ShouldPassByDefault() throws Exception {
        StringBuilder mail = new StringBuilder();
        DKIMVerifier verifier = signAndVerify(2048, "rsa-sha1", new VerifierOptions.Builder(), mail, new AtomicInteger());

        assertThat(verifier.verify(new ByteArrayInputStream(mail.toString().getBytes(StandardCharsets.US_ASCII)))).hasSize(1);
    }

    @Test
    public void rsaSha256ShouldPassWhenRsaSha1IsDisallowed() throws Exception {
        StringBuilder mail = new StringBuilder();
        DKIMVerifier verifier = signAndVerify(2048, "rsa-sha256", new VerifierOptions.Builder().withRsaSha1Allowed(false), mail, new AtomicInteger());

        assertThat(verifier.verify(new ByteArrayInputStream(mail.toString().getBytes(StandardCharsets.US_ASCII)))).hasSize(1);
    }

    @Test
    public void signaturesBrokenOnTheirOwnShouldBeRejectedWithoutKeyLookup() {
        AtomicInteger calls = new AtomicInteger();
        PublicKeyRecordRetriever retriever = (method, selector, token) -> {
            calls.incrementAndGet();
            throw new TempFailException("DNS timeout");
        };
        String valid = "bh=frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=; b=AAAA";
        String mail =
                "DKIM-Signature: v=1; a=rsa-sha256; c=foo; d=example.com; s=s0; h=from; " + valid + "\r\n"
                        + "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/foo; d=example.com; s=s1; h=from; " + valid + "\r\n"
                        + "DKIM-Signature: v=1; a=rsa-sha999; d=example.com; s=s2; h=from; " + valid + "\r\n"
                        + "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=s3; h=from; bh=frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=; b=A\r\n"
                        + "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=s4; h=from; bh=A; b=AAAA\r\n"
                        + "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=s5; h=from; l=x; " + valid + "\r\n"
                        + "From: joe@example.com\r\n\r\nbody\r\n";
        DKIMVerifier verifier = new DKIMVerifier(retriever);

        assertThatThrownBy(() -> verifier.verify(new ByteArrayInputStream(mail.getBytes(StandardCharsets.US_ASCII))))
                .isInstanceOf(FailException.class);
        assertThat(calls.get()).isZero();
        assertThat(verifier.getResults()).hasSize(6)
                .allMatch(r -> r.getResultType() == Result.Type.PERMERROR);
    }

    @Test
    public void wellFormedSignatureShouldStillGetATemperrorWhenTheLookupFails() {
        PublicKeyRecordRetriever retriever = (method, selector, token) -> {
            throw new TempFailException("DNS timeout");
        };
        String mail = "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=s0; h=from; "
                + "bh=frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=; b=AAAA\r\n"
                + "From: joe@example.com\r\n\r\nbody\r\n";
        DKIMVerifier verifier = new DKIMVerifier(retriever);

        assertThatThrownBy(() -> verifier.verify(new ByteArrayInputStream(mail.getBytes(StandardCharsets.US_ASCII))))
                .isInstanceOf(TempFailException.class);
        assertThat(verifier.getResults()).extracting(Result::getResultType).containsExactly(Result.Type.TEMPERROR);
    }
}
