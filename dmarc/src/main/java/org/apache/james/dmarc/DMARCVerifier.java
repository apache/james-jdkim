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
package org.apache.james.dmarc;

import org.apache.james.dmarc.exceptions.DmarcException;
import org.apache.james.mime4j.dom.Message;

public class DMARCVerifier {
    public static final String FROM = "From";
    private final String _dmarcResponse;
    private final String _dmarcNonResponse;
    private final PublicKeyRecordRetrieverDmarc _recordRetriever;

    public DMARCVerifier(String dmarcResponse, String dmarcNonResponse, PublicKeyRecordRetrieverDmarc recordRetriever) {
        _dmarcResponse = dmarcResponse;
        _dmarcNonResponse = dmarcNonResponse;
        _recordRetriever = recordRetriever;
    }

    public String runDmarcCheck(Message message, String spfHeaderText, String
            spfDomain, String dkimResult, String dkimDomain){
             // Combine SPF + DKIM results with From: domain
        // 1. Extract RFC5322.From domain from the From header of the message
        String shortSpfResult = spfHeaderText.split(" ")[0];
        String fromHeader = message.getHeader().getField(FROM).getBody();
        String fromDomain = extractDomain(fromHeader);
        if (fromDomain == null || fromDomain.isEmpty()) {
            return _dmarcNonResponse + "unknown";
        }

        // 2. Fetch DMARC record from DNS
        String dmarcRecord = _recordRetriever.getDmarcRecord(fromDomain);
        if (dmarcRecord == null) {
            return _dmarcNonResponse + fromDomain;
        }

        // Parse DMARC policy
        String policy = parseTag(dmarcRecord, "p"); // p=none|quarantine|reject
        String aspf = parseTag(dmarcRecord, "aspf"); // "s" or "r" for strict or relaxed domain alignment; default is "r"
        String adkim = parseTag(dmarcRecord, "adkim"); // "s" or "r" for strict or relaxed domain alignment; default is "r"

        // 3. Alignment checks
        boolean spfAligned = getDomainAlignment(aspf, shortSpfResult, fromDomain, spfDomain);
        boolean dkimAligned = getDomainAlignment(adkim, dkimResult, fromDomain, dkimDomain);

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

    private boolean getDomainAlignment(String flag, String result, String receivedDomain, String expectedDomain) {
        // we expect flag to be either "s" or "r"; default is "r"
        if (flag == null || flag.equalsIgnoreCase("r")){ //relaxed
            String fromOrgDomain = PublicSuffixList.getOrgDomain(receivedDomain); //we get the organizational domain using PSL
            String spfOrgDomain = PublicSuffixList.getOrgDomain(expectedDomain);

            return  "pass".equals(result)
                    && fromOrgDomain.equalsIgnoreCase(spfOrgDomain);
        }
        else if (flag.equalsIgnoreCase("s")){  // strict
            return "pass".equals(result) && receivedDomain.equalsIgnoreCase(expectedDomain);
        }
        else {
            throw new DmarcException(String.format("Unknown alignment flag value: %s", flag));
        }
    }

    private String extractDomain(String fromHeader) throws DmarcException {
        if (fromHeader == null || fromHeader.isEmpty()) {
            throw new DmarcException("From header is empty");
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
                throw new DmarcException("Invalid From header: " + fromHeader);
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
            throw new DmarcException("Invalid email address: " + fromHeader);
        }
        return address.substring(atIndex + 1);
    }

    public String parseTag(String dmarcRecord, String tag) {
        String[] parts = dmarcRecord.split(";");
        for (String part : parts) {
            String trimmed = part.trim();
            if (trimmed.startsWith(tag + "=")) {
                return trimmed.substring((tag + "=").length());
            }
        }
        return null;
    }
}
