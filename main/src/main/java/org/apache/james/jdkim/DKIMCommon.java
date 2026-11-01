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

import org.apache.james.jdkim.api.HashMethod;
import org.apache.james.jdkim.api.Headers;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.tagvalue.SignatureRecordImpl;
import org.apache.james.jdkim.api.SigningAlgorithm;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public abstract class DKIMCommon {

    private static final boolean DEEP_DEBUG = false;

    /**
     * The JCA signature algorithm of a signature record, from a fixed map rather than from the a= value:
     * only the RFC 6376 section 3.3 algorithms are accepted.
     *
     * @throws PermFailException for any other a= value
     */
    protected static String jcaSignatureAlgorithm(SignatureRecord sign) throws PermFailException {
        try {
            HashMethod hashMethod = SignatureRecordImpl.checkAlgorithm(sign);
            return SigningAlgorithm.RSA.asJdkSignatureAlgorithm(hashMethod);
        } catch (IllegalStateException e) {
            throw new PermFailException(e.getMessage(), sign, e);
        }
    }

    /**
     * Header fields are carried as Strings where each char is one raw octet
     * (see {@link Headers}): ISO-8859-1 gives them back unchanged.
     *
     * @throws IllegalArgumentException on a char above U+00FF, which getBytes
     *                                  would silently turn into '?'
     */
    private static byte[] octets(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) > 0xFF) {
                throw new IllegalArgumentException("Header field holds a char above U+00FF at " + i
                        + ": header fields must carry one octet per char");
            }
        }
        return s.getBytes(StandardCharsets.ISO_8859_1);
    }

    protected static void updateSignature(Signature signature,
                                          boolean relaxed,
                                          CharSequence header,
                                          String fv) throws SignatureException {
        if (relaxed) {
            if (DEEP_DEBUG)
                System.out
                        .println("#" + header.toString().toLowerCase(Locale.US) + ":-");
            signature.update(octets(header.toString().toLowerCase(Locale.US)));
            signature.update(octets(":"));
            String headerValue = fv.substring(fv.indexOf(':') + 1);
            headerValue = headerValue.replaceAll("\r\n[\t ]", " ");
            headerValue = headerValue.replaceAll("[\t ]+", " ");
            // RFC 6376 section 3.4.2 only deletes WSP: String#trim would also drop control characters
            headerValue = headerValue.replaceAll("^ | $", "");
            signature.update(octets(headerValue));
            if (DEEP_DEBUG)
                System.out.println("#" + headerValue + "#");
        } else {
            signature.update(octets(fv));
            if (DEEP_DEBUG)
                System.out.println("#" + fv + "#");
        }
    }

    protected static void signatureCheck(Headers h, SignatureRecord sign,
                                         List<CharSequence> headers, Signature signature)
            throws SignatureException, PermFailException {
        signatureCheck(h, sign, headers, signature, "DKIM-Signature");
    }

    /**
     * @param signatureFieldName the name of the DKIM-Signature field as written in
     *                           the message, i.e. the text before its colon: simple
     *                           canonicalization hashes it unchanged.
     */
    protected static void signatureCheck(Headers h, SignatureRecord sign,
                                         List<CharSequence> headers, Signature signature,
                                         String signatureFieldName)
            throws SignatureException, PermFailException {
        try {
            hashHeaders(h, sign, headers, signature, signatureFieldName);
        } catch (IllegalArgumentException e) {
            throw new PermFailException(e.getMessage(), sign, e);
        }
    }

    private static void hashHeaders(Headers h, SignatureRecord sign,
                                    List<CharSequence> headers, Signature signature,
                                    String signatureFieldName)
            throws SignatureException, PermFailException {

        boolean relaxedHeaders = SignatureRecord.RELAXED.equals(sign.getHeaderCanonicalisationMethod());
        if (!relaxedHeaders
                && !SignatureRecord.SIMPLE.equals(sign.getHeaderCanonicalisationMethod())) {
            throw new PermFailException("Unsupported canonicalization algorythm: "
                    + sign.getHeaderCanonicalisationMethod(), sign);
        }

        // NOTE: this could be improved by using iterators.
        // NOTE: this relies on the list returned by Message being in insertion
        // order
        Map<String, Integer> processedHeader = new HashMap<>();
        // Each distinct name is fetched once: h= may repeat a name many times.
        Map<String, List<String>> fieldsByName = new HashMap<>();

        for (CharSequence header : headers) {
            String lowerCaseHeader = header.toString().toLowerCase(Locale.US);
            List<String> hl = fieldsByName.computeIfAbsent(lowerCaseHeader, h::getFields);
            if (hl != null && !hl.isEmpty()) {
                Integer done = processedHeader.get(lowerCaseHeader);
                if (done == null)
                    done = 0;
                int doneHeaders = done + 1;
                if (doneHeaders <= hl.size()) {
                    String fv = hl.get(hl.size() - doneHeaders);
                    updateSignature(signature, relaxedHeaders, header, fv);
                    signature.update(octets("\r\n"));
                    processedHeader.put(lowerCaseHeader, doneHeaders);
                }
            }
        }

        String signatureStub = signatureFieldName + ":" + sign.toUnsignedString();
        updateSignature(signature, relaxedHeaders, "dkim-signature", signatureStub);
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
