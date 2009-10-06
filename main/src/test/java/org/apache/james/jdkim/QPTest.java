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

import junit.framework.TestCase;

public class QPTest extends TestCase {
	
	public void testDecode() {
		assertEquals("",CodecUtil.dkimQuotedPrintableDecode(""));
		assertEquals("@",CodecUtil.dkimQuotedPrintableDecode("=40"));
		assertEquals("\r\n",CodecUtil.dkimQuotedPrintableDecode("=0D=0A"));
		assertEquals("\0CIAO\0",CodecUtil.dkimQuotedPrintableDecode("=00CIAO=00"));
		assertEquals("thisisatest",CodecUtil.dkimQuotedPrintableDecode("this\r\n\tis\r\n a\r\n  \t test"));
	}
	
	public void testWhiteSpaces() {
		assertEquals("thisisatest",CodecUtil.dkimQuotedPrintableDecode("this is a test"));
		assertEquals("thisisatest",CodecUtil.dkimQuotedPrintableDecode("this\r\n is a test"));
	}
	
	public void testInvalid() {
		try {
			CodecUtil.dkimQuotedPrintableDecode("=");
			fail("invalid sequence parsed.");
		} catch (IllegalArgumentException e) {
		}
		try {
			CodecUtil.dkimQuotedPrintableDecode("==");
			fail("invalid sequence parsed.");
		} catch (IllegalArgumentException e) {
		}
		try {
			CodecUtil.dkimQuotedPrintableDecode("=2 3");
			fail("invalid sequence parsed.");
		} catch (IllegalArgumentException e) {
		}
		try {
			CodecUtil.dkimQuotedPrintableDecode("=3");
			fail("invalid sequence parsed.");
		} catch (IllegalArgumentException e) {
		}
		try {
			CodecUtil.dkimQuotedPrintableDecode("=3a");
			fail("invalid sequence parsed.");
		} catch (IllegalArgumentException e) {
		}
		try {
			CodecUtil.dkimQuotedPrintableDecode("==20");
			fail("invalid sequence parsed.");
		} catch (IllegalArgumentException e) {
		}
		try {
			CodecUtil.dkimQuotedPrintableDecode("=20=");
			fail("invalid sequence parsed.");
		} catch (IllegalArgumentException e) {
		}
		try {
			CodecUtil.dkimQuotedPrintableDecode("=3x");
			fail("invalid sequence parsed.");
		} catch (IllegalArgumentException e) {
		}
		try {
			CodecUtil.dkimQuotedPrintableDecode("this\r\nis a test");
			fail("invalid sequence parsed.");
		} catch (IllegalArgumentException e) {
		}
	}
	
	// TODO check bytes > 128
	/*
	public void test8bit() {
		assertEquals("PROVA\144CIAO\144",Main.dkimQuotedPrintableDecode("PROVA=90CIAO=90"));
	}
	*/

}
