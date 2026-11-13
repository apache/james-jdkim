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

package org.apache.james.jdkim.impl;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import org.junit.Test;

public class MessageFieldNameCaseTest {

    // ISO-8859-1: 0xf6 o-umlaut, 0xe3 a-tilde, 0xc3 A-tilde
    private static final String LOWER = "\u00f6\u00e3";
    private static final String UPPER = "\u00f6\u00c3";

    @Test
    public void getFieldsShouldFoldOnlyAsciiLetters() throws Exception {
        byte[] raw = (LOWER + ": a\r\n" + UPPER + ": b\r\n\r\nbody\r\n").getBytes(StandardCharsets.ISO_8859_1);
        Message message = new Message(new ByteArrayInputStream(raw));

        assertThat(message.getFields(LOWER)).containsExactly(LOWER + ": a");
        assertThat(message.getFields(UPPER)).containsExactly(UPPER + ": b");
    }

    @Test
    public void getFieldsShouldStillFoldAsciiLetters() throws Exception {
        byte[] raw = "From: a\r\nfROM: b\r\n\r\nbody\r\n".getBytes(StandardCharsets.ISO_8859_1);
        Message message = new Message(new ByteArrayInputStream(raw));

        assertThat(message.getFields("from")).containsExactly("From: a", "fROM: b");
        assertThat(message.getFields("FROM")).containsExactly("From: a", "fROM: b");
    }
}
