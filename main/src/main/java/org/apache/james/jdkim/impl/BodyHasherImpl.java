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

package org.apache.james.jdkim.impl;

import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.james.jdkim.api.BodyHasher;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.canon.DebugOutputStream;
import org.apache.james.jdkim.canon.DigestOutputStream;
import org.apache.james.jdkim.canon.LimitedOutputStream;
import org.apache.james.jdkim.canon.RelaxedBodyCanonicalizer;
import org.apache.james.jdkim.canon.SimpleBodyCanonicalizer;

public class BodyHasherImpl implements BodyHasher {

    private static final boolean DEEP_DEBUG = false;
    private SignatureRecord sign;
    private DigestOutputStream digesterOS;
    private OutputStream out;

    public BodyHasherImpl(SignatureRecord sign) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(sign.getHashAlgo()
                .toString());

        int limit = sign.getBodyHashLimit();

        // TODO enhance this to use a lookup service.
        boolean relaxedBody = "relaxed".equals(sign
                .getBodyCanonicalisationMethod());

        DigestOutputStream dout = new DigestOutputStream(md);

        OutputStream out = dout;
        if (DEEP_DEBUG)
            out = new DebugOutputStream(out);
        out = prepareCanonicalizerOutputStream(limit, relaxedBody, out);

        setSignatureRecord(sign);
        setDigestOutputStream(dout);
        setOutputStream(out);
    }

    static OutputStream prepareCanonicalizerOutputStream(int limit,
            boolean relaxedBody, OutputStream dout) {
        OutputStream out = dout;
        if (limit != -1)
            out = new LimitedOutputStream(out, limit);
        if (relaxedBody)
            out = new RelaxedBodyCanonicalizer(out);
        else
            out = new SimpleBodyCanonicalizer(out);
        return out;
    }

    /**
     * @see org.apache.james.jdkim.api.BodyHasher#getOutputStream()
     */
    public OutputStream getOutputStream() {
        return out;
    }

    /**
     * @see org.apache.james.jdkim.api.BodyHasher#getSignatureRecord()
     */
    public SignatureRecord getSignatureRecord() {
        return sign;
    }

    private DigestOutputStream getDigesterOutputStream() {
        return digesterOS;
    }

    /**
     * @see org.apache.james.jdkim.api.BodyHasher#getDigest()
     */
    public byte[] getDigest() {
        return getDigesterOutputStream().getDigest();
    }

    public void setSignatureRecord(SignatureRecord sign) {
        this.sign = sign;
    }

    public void setDigestOutputStream(DigestOutputStream dout) {
        this.digesterOS = dout;
    }

    public void setOutputStream(OutputStream out) {
        this.out = out;
    }

}
