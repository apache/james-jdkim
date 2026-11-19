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
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
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

    private static final byte[] COLON = {':'};
    private static final byte[] CRLF = {'\r', '\n'};

    protected static void updateSignature(Signature signature,
                                          boolean relaxed,
                                          CharSequence header,
                                          String fv) throws SignatureException {
        if (relaxed) {
            if (DEEP_DEBUG)
                System.out
                        .println("#" + Headers.lowerCaseFieldName(header) + ":-");
            signature.update(octets(Headers.lowerCaseFieldName(header)));
            signature.update(COLON);
            byte[] headerValue = relaxedValue(fv);
            signature.update(headerValue);
            if (DEEP_DEBUG)
                System.out.println("#" + new String(headerValue, StandardCharsets.ISO_8859_1) + "#");
        } else {
            signature.update(octets(fv));
            if (DEEP_DEBUG)
                System.out.println("#" + fv + "#");
        }
    }

    /**
     * The relaxed canonicalization of the value of a field (RFC 6376 section 3.4.2), in one pass: a CRLF
     * followed by WSP is unfolded, each run of WSP becomes a single SP, and the WSP at the start and at the end
     * of the value is deleted. Only WSP is deleted, never control characters, and a CRLF that is not followed
     * by WSP is kept as is.
     *
     * @param fv the field, name included: the value is what follows the first colon
     * @throws IllegalArgumentException on a char above U+00FF, see {@link #octets(String)}
     */
    static byte[] relaxedValue(String fv) {
        int n = fv.length();
        int start = fv.indexOf(':') + 1;
        byte[] out = new byte[n - start];
        int o = 0;
        boolean pendingWsp = false;
        for (int i = start; i < n; i++) {
            char c = fv.charAt(i);
            if (c == ' ' || c == '\t') {
                pendingWsp = true;
                continue;
            }
            if (c == '\r' && i + 2 < n && fv.charAt(i + 1) == '\n'
                    && (fv.charAt(i + 2) == ' ' || fv.charAt(i + 2) == '\t')) {
                // unfolding: the CRLF goes, the WSP after it is handled by the next iteration
                pendingWsp = true;
                i++;
                continue;
            }
            if (c > 0xFF) {
                throw new IllegalArgumentException("Header field holds a char above U+00FF at " + i
                        + ": header fields must carry one octet per char");
            }
            if (pendingWsp && o > 0) {
                out[o++] = ' ';
            }
            pendingWsp = false;
            out[o++] = (byte) c;
        }
        // WSP still pending ends the value: it is deleted
        return o == out.length ? out : Arrays.copyOf(out, o);
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
            String lowerCaseHeader = Headers.lowerCaseFieldName(header);
            List<String> hl = fieldsByName.computeIfAbsent(lowerCaseHeader, h::getFields);
            if (hl != null && !hl.isEmpty()) {
                Integer done = processedHeader.get(lowerCaseHeader);
                if (done == null)
                    done = 0;
                int doneHeaders = done + 1;
                if (doneHeaders <= hl.size()) {
                    String fv = hl.get(hl.size() - doneHeaders);
                    updateSignature(signature, relaxedHeaders, header, fv);
                    signature.update(CRLF);
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
