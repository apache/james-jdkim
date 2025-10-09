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
    public static final String FROM = "From";
    public static final String HEADER_I = "header.i=";
    private final PublicKeyRetrieverArc _keyRecordRetriever;
    private String _dmarcNoneResponse;
    private String _dmarcResponse;
    private String _authService;

    public AuthResultsBuilder(String dmarcResponse, String dmarcNoneResponse, String authService, PublicKeyRetrieverArc keyRecordRetriever) {
        this._dmarcResponse = dmarcResponse;
        this._dmarcNoneResponse = dmarcNoneResponse;
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
        String dmarcResult = runDmarcCheck(message, spfResultText, spfDomain, dkimResultShort, dkimDomain);
        if (dmarcResult == null || dmarcResult.isEmpty()) {
            dmarcResult = _dmarcNoneResponse + spfDomain;
        }

        return _authService + "; " +
                "spf=" + spfResultText.replace(";", "") + "; " +
                "dkim=" + dkimResultFull + "; " +
                dmarcResult;

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
                String iTag = (String) signatureRecord.getIdentity();
                if (iTag == null || iTag.isEmpty()) {
                    iTag = (String) signatureRecord.getDToken();
                }
                iTag = iTag.replace("@", ""); //most implementations drop the leading @
                CharSequence sTag = signatureRecord.getSelector();
                Set<String> tags = ((SignatureRecordImpl) signatureRecord).getTags();
                String bTag = "";
                if (!tags.isEmpty() && tags.contains("b")) {
                    byte[] signature = signatureRecord.getSignature();
                    bTag = Base64.getEncoder().encodeToString(signature);
                    bTag=bTag.substring(0,8);
                }
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

    private String runDmarcCheck(Message message, String spfHeaderText, String spfDomain, String dkim, String dkimDomain) {
        // Combine SPF + DKIM results with From: domain
        // 1. Extract RFC5322.From domain from the From header of the message
        String shortSpfResult = spfHeaderText.split(" ")[0];
        String fromHeader = message.getHeader().getField(FROM).getBody();
        String fromDomain = extractDomain(fromHeader);
        if (fromDomain == null || fromDomain.isEmpty()) {
            return _dmarcNoneResponse + "unknown";
        }

        // 2. Fetch DMARC record from DNS
        ARCVerifier arcVerifier = new ARCVerifier(_keyRecordRetriever);

        String dmarcRecord = arcVerifier.getPublicKeyRecordRetriever().getDmarcRecord(fromDomain);
        if (dmarcRecord == null) {
            return _dmarcNoneResponse + fromDomain;
        }

        // Parse DMARC policy
        String policy = arcVerifier.parseTagGeneric(dmarcRecord, "p"); // p=none|quarantine|reject
//            String aspf = parseTag(dmarcRecord, "aspf"); // optional
//            String adkim = parseTag(dmarcRecord, "adkim"); // optional

        // 3. Alignment checks
        boolean spfAligned = "pass".equals(shortSpfResult) && fromDomain.equalsIgnoreCase(spfDomain);
        boolean dkimAligned = "pass".equals(dkim) && fromDomain.equalsIgnoreCase(dkimDomain);

        // 4. DMARC result logic
        String result;
        if (spfAligned || dkimAligned) {
            result = "pass";
        } else {
            result = "fail";
        }

        // 5. Build Authentication-Results string
        return String.format(_dmarcResponse, result, policy, fromDomain);
    }

    // Using own parser to avoid dependency on javax.mail which does not handle all From: formats
    // e.g. From: "dpw demo Date: Wed, 8 Oct 2025 15:36:51 -0400" <dexxx8193@demo.test.io>"
    private String extractDomain(String fromHeader) throws ArcException {
        if (fromHeader == null || fromHeader.isEmpty()) {
            throw new ArcException("From header is empty");
        }

        // Extract address inside <...>
        String address = fromHeader;
        int lt = fromHeader.indexOf('<');
        int gt = fromHeader.indexOf('>');
        if (lt != -1 && gt != -1 && gt > lt) {
            address = fromHeader.substring(lt + 1, gt).trim();
        } else {
            // No brackets — just finding raw address
            int at = fromHeader.indexOf('@');
            if (at == -1) {
                throw new ArcException("Invalid From header: " + fromHeader);
            }

            // Lookin for something@domain
            String[] parts = fromHeader.split("\\s+");
            for (String part : parts) {
                if (part.contains("@")) {
                    address = part;
                    break;
                }
            }
        }

        // And finally extracting the domain
        int atIndex = address.lastIndexOf('@');
        if (atIndex == -1 || atIndex == address.length() - 1) {
            throw new ArcException("Invalid email address: " + fromHeader);
        }

        return address.substring(atIndex + 1);
    }

    private InputStream messageToInputStream(Message message) throws IOException {
        DefaultMessageWriter writer = new DefaultMessageWriter();
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        writer.writeEntity(message,os);
        return new ByteArrayInputStream(os.toByteArray());
    }
}
