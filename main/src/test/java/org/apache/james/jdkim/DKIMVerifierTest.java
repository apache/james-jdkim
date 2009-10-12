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

import org.apache.james.jdkim.api.PublicKeyRecord;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.tagvalue.PublicKeyRecordImpl;
import org.apache.james.jdkim.tagvalue.SignatureRecordImpl;

import junit.framework.TestCase;

public class DKIMVerifierTest extends TestCase {

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
        } catch (PermFailException e) {
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

}
