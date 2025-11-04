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

public class PublicSuffixListTest {

    /*
        `example.com` does not exist in the PSL, only `com` does
        so returning the `com` plus one label before it.
    */
    @Test
    public void getOrgDomain_simpleMatch() {
        assertEquals("example.com", PublicSuffixList.getOrgDomain("example.com"));
        assertEquals("example.com", PublicSuffixList.getOrgDomain("aaa.example.com"));
        assertEquals("example.com", PublicSuffixList.getOrgDomain("bbb.aaa.example.com"));
    }

    /*
    Domains not covered by PSL → fallback
    (should just return original domain)
    */
    @Test
    public void getOrgDomain_noPslMatch() {
        assertEquals("unknown.private", PublicSuffixList.getOrgDomain("unknown.private"));
        assertEquals("my.localdomain", PublicSuffixList.getOrgDomain("my.localdomain"));
        assertEquals("service.internal", PublicSuffixList.getOrgDomain("service.internal"));
    }

    @Test
    public void getOrgDomain_shouldReturnPublicSuffixIfMatched() {
        assertEquals("example.co.uk", PublicSuffixList.getOrgDomain("example.co.uk"));
        assertEquals("mail.replit.app", PublicSuffixList.getOrgDomain("mail.replit.app"));
    }

    /*
        *.sapporo.jp is a wild card rule
    */
    @Test
    public void getOrgDomain_wildCardMatched() {
        assertEquals("sapporo.jp", PublicSuffixList.getOrgDomain("sapporo.jp"));
        assertEquals("abc.sapporo.jp", PublicSuffixList.getOrgDomain("abc.sapporo.jp"));
        assertEquals("foo.abc.sapporo.jp", PublicSuffixList.getOrgDomain("foo.abc.sapporo.jp"));
        assertEquals("foo.abc.sapporo.jp", PublicSuffixList.getOrgDomain("bar.foo.abc.sapporo.jp"));
    }

    /*
        !city.sapporo.jp is an exception rule
    */
    @Test
    public void getOrgDomain_exceptionsMatched() {
        assertEquals("city.sapporo.jp", PublicSuffixList.getOrgDomain("city.sapporo.jp"));
        assertEquals("city.sapporo.jp", PublicSuffixList.getOrgDomain("abc.city.sapporo.jp"));
        assertEquals("city.sapporo.jp", PublicSuffixList.getOrgDomain("x.y.city.sapporo.jp"));
    }

    /*
     *.ck
     !www.ck
     Wildcard with exception
 */
    @Test
    public void getOrgDomain_wildCardAndExceptionCombo() {
        assertEquals("www.ck", PublicSuffixList.getOrgDomain("www.ck"));                 // exception
        assertEquals("www.ck", PublicSuffixList.getOrgDomain("a.www.ck"));               // exception overrides wildcard
        assertEquals("abc.ck", PublicSuffixList.getOrgDomain("abc.ck"));                 // wildcard + one left
        assertEquals("foo.abc.ck", PublicSuffixList.getOrgDomain("foo.abc.ck"));         // wildcard + two left
        assertEquals("foo.abc.ck", PublicSuffixList.getOrgDomain("bar.foo.abc.ck"));     // wildcard + two. we stop at two left labels
    }

    /*
     single-label domains should return themselves
     */
    @Test
    public void getOrgDomain_singleLabel() {
        assertEquals("localhost", PublicSuffixList.getOrgDomain("localhost"));
        assertEquals("com", PublicSuffixList.getOrgDomain("com"));
        assertEquals("example", PublicSuffixList.getOrgDomain("example"));
    }

    /*
    PSL match with internationalized domain names (IDN)
    */
    @Test
    public void getOrgDomain_openAiWildcard() {
        assertEquals("三重.jp", PublicSuffixList.getOrgDomain("三重.jp"));                  //Bare PSL match
        assertEquals("北海道.三重.jp", PublicSuffixList.getOrgDomain("北海道.三重.jp"));      //PSL + one left
        assertEquals("北海道.三重.jp", PublicSuffixList.getOrgDomain("大分.北海道.三重.jp"));  //PSL + two left
    }
}