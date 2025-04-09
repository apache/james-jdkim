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

package org.apache.james.jdkim.parser;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class DKIMQuotedPrintableTest {

    @Test
    public void testQPDecode() {
        assertEquals("", DKIMQuotedPrintable.dkimQuotedPrintableDecode(""));
        assertEquals("@", DKIMQuotedPrintable.dkimQuotedPrintableDecode("=40"));
        assertEquals("\r\n", DKIMQuotedPrintable
                .dkimQuotedPrintableDecode("=0D=0A"));
        assertEquals("\0CIAO\0", DKIMQuotedPrintable
                .dkimQuotedPrintableDecode("=00CIAO=00"));
        assertEquals("thisisatest", DKIMQuotedPrintable
                .dkimQuotedPrintableDecode("this\r\n\tis\r\n a\r\n  \t test"));
    }

    @Test
    public void testQPWhiteSpaces() {
        assertEquals("thisisatest", DKIMQuotedPrintable
                .dkimQuotedPrintableDecode("this is a test"));
        assertEquals("thisisatest", DKIMQuotedPrintable
                .dkimQuotedPrintableDecode("this\r\n is a test"));
    }

    @Test
    public void testQPInvalid() {
        assertThatThrownBy(()->
                DKIMQuotedPrintable.dkimQuotedPrintableDecode("=")
            ).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid quoted printable termination");

        assertThatThrownBy(()->
                DKIMQuotedPrintable.dkimQuotedPrintableDecode("==")
        ).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid input sequence at");

        assertThatThrownBy(()->
                DKIMQuotedPrintable.dkimQuotedPrintableDecode("=2 3")
        ).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid input sequence at");

        assertThatThrownBy(()->
                DKIMQuotedPrintable.dkimQuotedPrintableDecode("=3")
        ).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid quoted printable termination");

        assertThatThrownBy(()->
                DKIMQuotedPrintable.dkimQuotedPrintableDecode("=3a")
        ).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid input sequence at");

        assertThatThrownBy(()->
                DKIMQuotedPrintable.dkimQuotedPrintableDecode("==20")
        ).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid input sequence at");

        assertThatThrownBy(()->
                DKIMQuotedPrintable.dkimQuotedPrintableDecode("=20=")
        ).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid quoted printable termination");

        assertThatThrownBy(()->
                DKIMQuotedPrintable.dkimQuotedPrintableDecode("=3x")
        ).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid input sequence at");

        assertThatThrownBy(()->
                DKIMQuotedPrintable.dkimQuotedPrintableDecode("this\r\nis a test")
        ).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unexpected LF not part of an FWS");
    }

    @Test
    public void test8bit() {
        assertEquals("smiling face ØÞ with heart eyes", DKIMQuotedPrintable.dkimQuotedPrintableDecode("smiling=20face=20=D8=DE=20with=20heart=20eyes"));
    }

    // TODO UTF-8 see https://datatracker.ietf.org/doc/html/rfc6376#section-3.2
}
