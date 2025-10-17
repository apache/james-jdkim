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

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

public class PublicSuffixListTest {

    @Test
    public void isPublicSuffix_shouldReturnTrueForKnownSuffix() {
        assertTrue(PublicSuffixList.isPublicSuffix("com"));
        assertTrue(PublicSuffixList.isPublicSuffix("CO.UK"));
        assertTrue(PublicSuffixList.isPublicSuffix("replit.app"));
        assertTrue(PublicSuffixList.isPublicSuffix("id.replit.app"));
    }

    @Test
    public void isPublicSuffix_shouldReturnFalseForUnknownSuffix() {
        assertFalse(PublicSuffixList.isPublicSuffix("example"));
        assertFalse(PublicSuffixList.isPublicSuffix("unknown.tld"));
        assertFalse(PublicSuffixList.isPublicSuffix("mail.replit.app"));
    }

    @Test
    public void getOrgDomain_shouldReturnPublicSuffixIfMatched() {
        assertEquals("co.uk", PublicSuffixList.getOrgDomain("example.co.uk"));
        assertEquals("replit.app", PublicSuffixList.getOrgDomain("mail.replit.app"));
    }

    @Test
    public void getOrgDomain_shouldNotReturnPublicSuffixIfNotMatched() {
        assertNotEquals("replit.app", PublicSuffixList.getOrgDomain("id.replit.app"));
        assertNotEquals("firewalledreplit.co", PublicSuffixList.getOrgDomain("id.firewalledreplit.co"));
    }

    @Test
    public void getOrgDomain_shouldReturnInputIfNoSuffixMatched() {
        assertEquals("mydomain.unknown", PublicSuffixList.getOrgDomain("mydomain.unknown"));
    }
}