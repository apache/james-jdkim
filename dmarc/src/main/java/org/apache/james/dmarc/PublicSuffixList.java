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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

public class PublicSuffixList {
    private static final Set<String> RULES = new HashSet<>();
    private static final Set<String> WILDCARDS = new HashSet<>();
    private static final Set<String> EXCEPTIONS = new HashSet<>();

    static {
        try (InputStream is = PublicSuffixList.class.getResourceAsStream("/public_suffix_list.dat")) {
            assert is != null;
            parsePsl(is);
        }
        catch (Exception e) {
            throw new DmarcException("Failed to load Public Suffix List", e);
        }
    }

    private static void parsePsl(InputStream is) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("//")) continue;
                if (line.startsWith("!")) {
                    EXCEPTIONS.add(line.substring(1).toLowerCase());
                } else if (line.startsWith("*.")) {
                    WILDCARDS.add(line.substring(2).toLowerCase());
                } else {
                    RULES.add(line.toLowerCase());
            }
        }
    } catch (IOException e) {
            throw new DmarcException("Failed to read Public Suffix List", e);
        }
    }

    private PublicSuffixList() {}

    public static String getOrgDomain(String domainToCheck) {
        if (domainToCheck == null || domainToCheck.trim().isEmpty()) return domainToCheck;

        domainToCheck = domainToCheck.toLowerCase(Locale.ROOT).trim();
        String[] domainParts = domainToCheck.split("\\.");
        int numParts = domainParts.length;

        PSLMatchOutcome outcome = null;

        for (int i = 0; i < numParts && outcome == null; i++) {
            String[] candidateArr = Arrays.copyOfRange(domainParts, i, numParts);
            String matchedCandidate = String.join(".", candidateArr);

            if (EXCEPTIONS.contains(matchedCandidate)) {
                // Exception rules take precedence
                outcome = new PSLMatchOutcome(PSLMatch.EXCEPTION, matchedCandidate, domainParts, i);
            }

            if (WILDCARDS.contains(matchedCandidate)) {
                outcome = new PSLMatchOutcome(PSLMatch.WILDCARD, matchedCandidate, domainParts, i);
            }

            if (RULES.contains(matchedCandidate)) {
                outcome = new PSLMatchOutcome(PSLMatch.RULE, matchedCandidate, domainParts, i);
            }
        }

        return outcome == null?
                new PSLMatchOutcome(PSLMatch.NONE, null, domainParts, -1).getRelaxedOrgDomain():
                outcome.getRelaxedOrgDomain();
    }
}