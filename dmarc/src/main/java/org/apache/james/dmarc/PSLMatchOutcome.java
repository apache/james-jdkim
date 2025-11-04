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
package org.apache.james.dmarc;

import java.util.Arrays;

public class PSLMatchOutcome {
    private final PSLMatch match;
    private final String matchedCandidate;
    private final String[] domainElements;
    private final int matchedIndex;

    public PSLMatchOutcome(PSLMatch matchType, String candidate, String[] domainParts, int index) {
        match = matchType;
        matchedCandidate = candidate;
        domainElements = domainParts;
        matchedIndex = index;
    }

    public String getRelaxedOrgDomain() {
        switch (match) {
            case RULE:
                return matchedIndex >= 1 ?
                    String.join(".", Arrays.copyOfRange(domainElements, matchedIndex - 1, domainElements.length)) :
                    String.join(".", Arrays.copyOfRange(domainElements, 0, domainElements.length));
            case WILDCARD:
                if (matchedIndex >= 2) {
                    return String.join(".", Arrays.copyOfRange(domainElements, matchedIndex - 2, domainElements.length));
                }
                else if (matchedIndex == 1) {
                    return String.join(".", Arrays.copyOfRange(domainElements, 0, domainElements.length));
                }
                else {
                    return matchedCandidate;
                }
            case EXCEPTION:
                return String.join(".", Arrays.copyOfRange(domainElements, matchedIndex, domainElements.length));
            case NONE:
            default:
                return String.join(".", Arrays.copyOfRange(domainElements, 0, domainElements.length));
        }
    }
}
