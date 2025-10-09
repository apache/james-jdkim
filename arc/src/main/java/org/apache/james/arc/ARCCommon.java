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
package org.apache.james.arc;

import org.apache.james.jdkim.api.Headers;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.exceptions.PermFailException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Signature;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
/**
 * Utility class for ARC (Authenticated Received Chain) operations.
 * <p>
 * Provides methods for:
 * <ul>
 *   <li>Canonicalizing and updating cryptographic signatures for ARC headers</li>
 *   <li>Signing ARC-Message-Signature and ARC-Seal headers</li>
 *   <li>Copying streams</li>
 *   <li>Decoding Base64-encoded PKCS#8 private keys</li>
 * </ul>
 * <p>
 * This class is not intended to be instantiated.
 */
public class ARCCommon {
    private ARCCommon(){}

    private static void updateSignature(Signature signature, boolean relaxed,
                                        CharSequence header, String fv) throws SignatureException {
        if (relaxed) {
            signature.update(header.toString().toLowerCase().getBytes());
            signature.update(":".getBytes());
            String headerValue = fv.substring(fv.indexOf(':') + 1);
            headerValue = headerValue.replaceAll("\r\n[\t ]", " ");
            headerValue = headerValue.replaceAll("[\t ]+", " ");
            headerValue = headerValue.trim();
            signature.update(headerValue.getBytes());
        } else {
            signature.update(fv.getBytes());
        }
    }

    static void amsSign(Headers h, SignatureRecord sign,
                        List<CharSequence> headers, Signature signature)
            throws SignatureException, PermFailException {

        boolean relaxedHeaders = isRelaxedHeaders(sign, true);

        Map<String, Integer> processedHeader = new HashMap<>();

        for (CharSequence header : headers) {
            List<String> hl = h.getFields(header.toString());
            if (hl != null && !hl.isEmpty()) {
                Integer done = processedHeader.get(header.toString());
                if (done == null)
                    done = 0;
                int doneHeaders = done + 1;
                if (doneHeaders <= hl.size()) {
                    String fv = hl.get(hl.size() - doneHeaders);
                    updateSignature(signature, relaxedHeaders, header, fv);
                    signature.update("\r\n".getBytes());
                    processedHeader.put(header.toString(), doneHeaders);
                }
            }
        }

        String amsHeader = "ARC-Message-Signature:" + sign.toUnsignedString();
        updateSignature(signature, relaxedHeaders, "arc-message-signature", amsHeader);
    }

    static void arcSeal(SignatureRecord sign,
                        Map<String, String> headersToSeal, Signature signature)
            throws SignatureException, PermFailException {

        boolean relaxedHeaders = isRelaxedHeaders(sign, false);

        for (Map.Entry<String, String> headerEntry : headersToSeal.entrySet()) {
            String headerName = headerEntry.getKey();
            String headerValue = headerName+": " +headerEntry.getValue();
            updateSignature(signature, relaxedHeaders, headerName, headerValue);
            signature.update("\r\n".getBytes());
        }

        String signatureStub = "ARC-Seal:" + sign.toUnsignedString();
        updateSignature(signature, relaxedHeaders, "arc-seal",
                signatureStub);
    }

    private static boolean isRelaxedHeaders(SignatureRecord sign, boolean isAms) throws PermFailException {
        boolean relaxedHeaders = !isAms || SignatureRecord.RELAXED.equals(sign
                .getHeaderCanonicalisationMethod()); // RFC 8617 : ARC-seal: only "relaxed" header field canonicalization allowed
        if (!relaxedHeaders
                && !SignatureRecord.SIMPLE.equals(sign
                .getHeaderCanonicalisationMethod())) {

            throw new PermFailException(
                    "Unsupported canonicalization algorithm: "
                            + sign.getHeaderCanonicalisationMethod());
        }
        return relaxedHeaders;
    }

    public static void streamCopy(InputStream bodyIs, OutputStream out)
            throws IOException {
        byte[] buffer = new byte[2048];
        int read;
        while ((read = bodyIs.read(buffer)) > 0) {
            out.write(buffer, 0, read);
        }
        bodyIs.close();
        out.close();
    }
}
