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
import java.util.Locale;
import java.util.Map;

public abstract class DKIMCommon {

    private static final boolean DEEP_DEBUG = false;

    protected static void updateSignature(Signature signature,
                                          boolean relaxed,
                                          CharSequence header,
                                          String fv) throws SignatureException {
        if (relaxed) {
            if (DEEP_DEBUG)
                System.out
                        .println("#" + header.toString().toLowerCase() + ":-");
            signature.update(header.toString().toLowerCase().getBytes());
            signature.update(":".getBytes());
            String headerValue = fv.substring(fv.indexOf(':') + 1);
            headerValue = headerValue.replaceAll("\r\n[\t ]", " ");
            headerValue = headerValue.replaceAll("[\t ]+", " ");
            headerValue = headerValue.trim();
            signature.update(headerValue.getBytes());
            if (DEEP_DEBUG)
                System.out.println("#" + headerValue + "#");
        } else {
            signature.update(fv.getBytes());
            if (DEEP_DEBUG)
                System.out.println("#" + fv + "#");
        }
    }

    protected static void signatureCheck(Headers h, SignatureRecord sign,
                                         List<CharSequence> headers, Signature signature)
            throws SignatureException, PermFailException {

        boolean relaxedHeaders = SignatureRecord.RELAXED.equals(sign.getHeaderCanonicalisationMethod());
        if (!relaxedHeaders
                && !SignatureRecord.SIMPLE.equals(sign.getHeaderCanonicalisationMethod())) {
            throw new PermFailException("Unsupported canonicalization algorythm: "
                    + sign.getHeaderCanonicalisationMethod());
        }

        // NOTE: this could be improved by using iterators.
        // NOTE: this relies on the list returned by Message being in insertion
        // order
        Map<String, Integer> processedHeader = new HashMap<String, Integer>();

        for (CharSequence header : headers) {
            // NOTE check this getter is case insensitive
            List<String> hl = h.getFields(header.toString());
            if (hl != null && hl.size() > 0) {
                Integer done = processedHeader.get(header.toString().toLowerCase(Locale.ENGLISH));
                if (done == null)
                    done = 0;
                int doneHeaders = done + 1;
                if (doneHeaders <= hl.size()) {
                    String fv = hl.get(hl.size() - doneHeaders);
                    updateSignature(signature, relaxedHeaders, header, fv);
                    signature.update("\r\n".getBytes());
                    processedHeader.put(header.toString().toLowerCase(Locale.ENGLISH), doneHeaders);
                }
            }
        }

        String signatureStub = "DKIM-Signature:" + sign.toUnsignedString();
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
