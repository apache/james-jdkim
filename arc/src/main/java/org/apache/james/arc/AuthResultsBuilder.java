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

import org.apache.james.arc.exceptions.ArcException;
import org.apache.james.dmarc.DMARCVerifier;
import org.apache.james.dmarc.DmarcValidationResult;
import org.apache.james.jdkim.DKIMVerifier;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.exceptions.FailException;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.exceptions.TempFailException;
import org.apache.james.jdkim.tagvalue.SignatureRecordImpl;
import org.apache.james.mime4j.dom.Message;
import org.apache.james.mime4j.message.DefaultMessageWriter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Builds the Authentication-Results header for email messages by performing SPF, DKIM, and DMARC checks.
 * <p>
 * This class runs SPF and DKIM verifications on the provided message and then evaluates DMARC alignment
 * using the results and the message's From domain. It constructs a formatted Authentication-Results header
 * string summarizing the authentication status.
 * </p>
 * <ul>
 *     <li>SPF: Uses the sender's IP, HELO, and envelope-from address.</li>
 *     <li>DKIM: Verifies DKIM signatures in the message.</li>
 *     <li>DMARC: Checks alignment and policy based on DNS records for the From domain.</li>
 * </ul>
 * <p>
 * Throws {@link org.apache.james.arc.exceptions.ArcException} for errors in the authentication process.
 * </p>
 */
public class AuthResultsBuilder {
    public static final String HEADER_I = "header.i=";
    private final PublicKeyRetrieverArc _keyRecordRetriever;
    private String _authService;

    public AuthResultsBuilder(String authService, PublicKeyRetrieverArc keyRecordRetriever) {
        this._authService = authService;
        this._keyRecordRetriever = keyRecordRetriever;
    }

    public String getAuthResultsHeader(Message message, String helo, String from, String ip) {

        // 1. Run SPF check
        String spfResultText  = _keyRecordRetriever.getSpfRecord(helo, from, ip);

        // 2. Run DKIM verification
        String dkimResultFull;
        try {
            dkimResultFull = runDkimCheck(message);
        } catch (IOException e) {
            throw new ArcException("IO Error while checking DKIM results", e);
        }
        String dkimResultShort = dkimResultFull.split(" ")[0];

        // 3. Run DMARC check (using SPF + DKIM results + From domain)
        String dkimDomain = extractDkimDomain(dkimResultFull);
        String spfDomain = extractSpfDomain(spfResultText);
        DMARCVerifier dmarcVerifier = new DMARCVerifier(_keyRecordRetriever.getDmarcRetriever());
        DmarcValidationResult dmarcResult = dmarcVerifier.runDmarcCheck(message, spfResultText, spfDomain, dkimResultShort, dkimDomain);

        return _authService + "; " +
                "spf=" + spfResultText.replace(";", "") + "; " +
                "dkim=" + dkimResultFull + "; " +
                dmarcResult.toString();
    }

    private String runDkimCheck(Message message) throws IOException {
        final DKIMVerifier verifier = new DKIMVerifier(_keyRecordRetriever);
        InputStream is = messageToInputStream(message);

        // Verify DKIM signatures
        List<SignatureRecord> results;
        try {
            results = verifier.verify(is);
            if (!results.isEmpty() && results.stream().allMatch(Objects::nonNull) && results.get(0) != null) {
                SignatureRecord signatureRecord = results.get(0);
                String iTag = computeITag(signatureRecord);
                CharSequence sTag = signatureRecord.getSelector();
                Set<String> tags = ((SignatureRecordImpl) signatureRecord).getTags();
                String bTag = computeBTag(tags, signatureRecord);
                String outcome = "pass";
                return outcome + " header.i=" + iTag + " header.s=" + sTag+ " header.b=" + bTag;
            }
        }
        catch (PermFailException e) {
            throw new ArcException("DKIM PermFail", e);
        } catch (TempFailException e) {
            throw new ArcException("DKIM TempFail", e);
        } catch (FailException e) {
            throw new ArcException("DKIM Fail", e);
        } catch (Exception e) {
            throw new ArcException("DKIM Error", e);
        }
        return "fail (no valid signature records)";
    }

    private static String computeITag(SignatureRecord signatureRecord) {
        String iTag = (String) signatureRecord.getIdentity();
        if (iTag == null || iTag.isEmpty()) {
            iTag = (String) signatureRecord.getDToken();
        }
        iTag = iTag.replace("@", ""); //most implementations drop the leading @
        return iTag;
    }

    private static String computeBTag(Set<String> tags, SignatureRecord signatureRecord) {
        String bTag = "";
        if (!tags.isEmpty() && tags.contains("b")) {
            byte[] signature = signatureRecord.getSignature();
            bTag = Base64.getEncoder().encodeToString(signature);
            bTag=bTag.substring(0,8);
        }
        return bTag;
    }

    private String extractSpfDomain(String spfHeaderText) {
        String[] parts = spfHeaderText.split(" ");
        for (String part : parts) {
            if (part.startsWith("envelope-from=")) {
                String[] subParts = part.substring("envelope-from=".length()).split("@");
                if (subParts.length < 2) return null;
                String envFrom = subParts[1];
                envFrom = envFrom.replaceAll("[<>]", "").replace(";", "");
                return envFrom.trim();
            }
        }
        return null;
    }

    private String extractDkimDomain(String dkimResultFull) {
        String[] parts = dkimResultFull.split(" ");
        for (String part : parts) {
            if (part.startsWith(HEADER_I)) {
                String partValue = part.substring(HEADER_I.length());
                if (partValue.contains("@")) //some implementations drop the leading @
                    return partValue.split("@")[1].trim();
                else
                    return partValue.trim();
            }
        }
        return null;
    }

    private InputStream messageToInputStream(Message message) throws IOException {
        DefaultMessageWriter writer = new DefaultMessageWriter();
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        writer.writeEntity(message,os);
        return new ByteArrayInputStream(os.toByteArray());
    }
}
