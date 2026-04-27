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

import java.util.Locale;

import com.google.common.net.InternetDomainName;

public class GuavaPublicSuffixList implements PublicSuffixList {
    @Override
    public String getOrgDomain(String domainToCheck) {
        if (domainToCheck == null || domainToCheck.trim().isEmpty()) {
            return domainToCheck;
        }

        String normalizedDomain = domainToCheck.toLowerCase(Locale.ROOT).trim();
        try {
            InternetDomainName domainName = InternetDomainName.from(normalizedDomain);
            if (domainName.isUnderPublicSuffix()) {
                return domainName.topPrivateDomain().toString();
            }
            return normalizedDomain;
        } catch (IllegalArgumentException e) {
            return normalizedDomain;
        }
    }
}
