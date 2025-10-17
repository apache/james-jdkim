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
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class PublicSuffixList {
    private static final Set<String> SUFFIXES = new HashSet<>();

    static {
        try (InputStream is = PublicSuffixList.class.getResourceAsStream("/public_suffix_list.dat")) {
            assert is != null;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("//")) continue;
                    SUFFIXES.add(line.toLowerCase());
                }
            }
        } catch (Exception e) {
            throw new DmarcException("Failed to load Public Suffix List", e);
        }
    }

    private PublicSuffixList() {}

    public static boolean isPublicSuffix(String domain) {
        return SUFFIXES.contains(domain.toLowerCase());
    }

    public static  String getOrgDomain(String receivedDomain) {
        String[] parts = receivedDomain.toLowerCase().split("\\.");
        for (int i = 0; i < parts.length - 1; i++) {
            //we start checking from the most specific part on the left moving to the right until we find a match
            String candidate = String.join(".", Arrays.copyOfRange(parts, i, parts.length));
            if (isPublicSuffix(candidate)) {
                return candidate;
            }
        }
        return receivedDomain;
    }

    static void main() {
        System.out.println(getOrgDomain("id.replit.app")); // example.co.uk
    }
}