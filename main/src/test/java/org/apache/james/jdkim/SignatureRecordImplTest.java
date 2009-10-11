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

package org.apache.james.jdkim;

import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.tagvalue.SignatureRecordImpl;

import junit.framework.TestCase;

public class SignatureRecordImplTest extends TestCase {

    public void testQPDecode() {
        assertEquals("", SignatureRecordImpl.dkimQuotedPrintableDecode(""));
        assertEquals("@", SignatureRecordImpl.dkimQuotedPrintableDecode("=40"));
        assertEquals("\r\n", SignatureRecordImpl
                .dkimQuotedPrintableDecode("=0D=0A"));
        assertEquals("\0CIAO\0", SignatureRecordImpl
                .dkimQuotedPrintableDecode("=00CIAO=00"));
        assertEquals("thisisatest", SignatureRecordImpl
                .dkimQuotedPrintableDecode("this\r\n\tis\r\n a\r\n  \t test"));
    }

    public void testQPWhiteSpaces() {
        assertEquals("thisisatest", SignatureRecordImpl
                .dkimQuotedPrintableDecode("this is a test"));
        assertEquals("thisisatest", SignatureRecordImpl
                .dkimQuotedPrintableDecode("this\r\n is a test"));
    }

    public void testQPInvalid() {
        try {
            SignatureRecordImpl.dkimQuotedPrintableDecode("=");
            fail("invalid sequence parsed.");
        } catch (IllegalArgumentException e) {
        }
        try {
            SignatureRecordImpl.dkimQuotedPrintableDecode("==");
            fail("invalid sequence parsed.");
        } catch (IllegalArgumentException e) {
        }
        try {
            SignatureRecordImpl.dkimQuotedPrintableDecode("=2 3");
            fail("invalid sequence parsed.");
        } catch (IllegalArgumentException e) {
        }
        try {
            SignatureRecordImpl.dkimQuotedPrintableDecode("=3");
            fail("invalid sequence parsed.");
        } catch (IllegalArgumentException e) {
        }
        try {
            SignatureRecordImpl.dkimQuotedPrintableDecode("=3a");
            fail("invalid sequence parsed.");
        } catch (IllegalArgumentException e) {
        }
        try {
            SignatureRecordImpl.dkimQuotedPrintableDecode("==20");
            fail("invalid sequence parsed.");
        } catch (IllegalArgumentException e) {
        }
        try {
            SignatureRecordImpl.dkimQuotedPrintableDecode("=20=");
            fail("invalid sequence parsed.");
        } catch (IllegalArgumentException e) {
        }
        try {
            SignatureRecordImpl.dkimQuotedPrintableDecode("=3x");
            fail("invalid sequence parsed.");
        } catch (IllegalArgumentException e) {
        }
        try {
            SignatureRecordImpl.dkimQuotedPrintableDecode("this\r\nis a test");
            fail("invalid sequence parsed.");
        } catch (IllegalArgumentException e) {
        }
    }

    // TODO check bytes > 128
    /*
     * public void test8bit() {
     * assertEquals("PROVA\144CIAO\144",Main.dkimQuotedPrintableDecode("PROVA=90CIAO=90")); }
     */

    /*
     * when we moved from Sun's Base64 to CommonsCodec the decoding changed
     * behaviour. it does no more fail on bad encoded data. public void
     * testWrongBase64Encoding() { SignatureRecord sr = new
     * SignatureRecordImpl("v=1; bh=0012=GG; b==GG;"); try { sr.getBodyHash();
     * fail("expected failure"); } catch (Exception e) {
     * assertTrue(e.getMessage().toLowerCase().contains("decod")); } try {
     * sr.getSignature(); fail("expected failure"); } catch (Exception e) {
     * assertTrue(e.getMessage().toLowerCase().contains("decod")); } }
     */

    public void testWrongHashSyntaxes() {
        SignatureRecord sr = new SignatureRecordImpl("v=1; a=nothyphenedword;");
        try {
            sr.getHashAlgo();
            fail("expected failure");
        } catch (Exception e) {
            assertTrue(e.getMessage().toLowerCase().indexOf("hash") != -1);
        }
        try {
            sr.getHashMethod();
            fail("expected failure");
        } catch (Exception e) {
            assertTrue(e.getMessage().toLowerCase().indexOf("hash") != -1);
        }
        try {
            sr.getHashAlgo();
            fail("expected failure");
        } catch (Exception e) {
            assertTrue(e.getMessage().toLowerCase().indexOf("hash") != -1);
        }
    }

    public void testExpired() {
        SignatureRecord sr = new SignatureRecordImpl(
                "v=1; c=simple; h=from:to; s=select; d=example.com; a=rsa-sha1; x=0; bh=abcdef; b=1235345987;");
        try {
            sr.validate();
            fail("expected failure");
        } catch (Exception e) {
            assertTrue(e.getMessage().indexOf("expired") != -1);
        }
    }

}
