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
import org.apache.james.mime4j.dom.address.Mailbox;
import org.apache.james.mime4j.dom.address.MailboxList;
import java.util.HashMap;
import java.util.Map;

public class DMARCVerifier {
    public static final String FROM = "From";
    private final PublicKeyRecordRetrieverDmarc _recordRetriever;

    public DMARCVerifier(PublicKeyRecordRetrieverDmarc recordRetriever) {
        _recordRetriever = recordRetriever;
    }

    public DmarcValidationResult runDmarcCheck(Message message, String spfHeaderText, String
            spfDomain, String dkimResult, String dkimDomain) throws DmarcException {
             // Combine SPF + DKIM results with From: domain
        // 1. Extract RFC5322.From domain from the From header of the message
        String shortSpfResult = spfHeaderText.split(" ")[0];
        MailboxList mailboxList = message.getFrom();
        if (mailboxList == null || mailboxList.size() != 1) {
            throw new DmarcException("Incorrect From header: must have exactly one mailbox"); // rejecting immediately unless exactly one mailbox
        }

        Mailbox mailbox = message.getFrom().get(0);
        String fromDomain = mailbox.getDomain();
        if (fromDomain == null || fromDomain.isEmpty()) {
            throw new DmarcException("From header is missing or has no domain part");
        }

        // 2. Fetch DMARC record from DNS
        String dmarcRecord = _recordRetriever.getDmarcRecord(fromDomain);
        if (dmarcRecord == null) {
            return new DmarcValidationResult(fromDomain, null, null);
        }

        // Parse DMARC policy
        Map<String, String> dmarcTags = getDmarcTags(dmarcRecord);
        String policy = dmarcTags.getOrDefault("p", "none");
        String aspf = dmarcTags.getOrDefault("aspf", "r");      // default is "r" when omitted
        String adkim = dmarcTags.getOrDefault("adkim", "r");    // default is "r" when omitted

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
        return new DmarcValidationResult(result, policy, fromDomain);
    }

    private Map<String, String> getDmarcTags(String dmarcRecord) {
        Map<String, String> dmarcTags = new HashMap<>();
        String[] parts = dmarcRecord.split(";");
        for (String part : parts) {
            String trimmed = part.trim();
            String[] tagValue = trimmed.split("=");
            if (tagValue.length == 2) {
                dmarcTags.put(tagValue[0].toLowerCase(), tagValue[1]);
            }
        }
        return dmarcTags;
    }

    private boolean getDomainAlignment(String flag, String result, String receivedDomain, String expectedDomain) {
        // we expect flag to be either "s" or "r"; default is "r" when omitted
        if (flag.equalsIgnoreCase("r")){ //relaxed
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
}
