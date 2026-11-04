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

package org.apache.james.jdkim.impl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import org.apache.james.jdkim.DKIMSigner;
import org.apache.james.jdkim.TestKeys;
import org.apache.james.mime4j.MimeException;
import org.junit.Test;

public class MessageLimitsTest {

    private static ByteArrayInputStream stream(StringBuilder sb) {
        return new ByteArrayInputStream(sb.toString().getBytes(StandardCharsets.US_ASCII));
    }

    @Test
    public void shouldParseMoreThanThousandHeaderFields() throws Exception {
        StringBuilder sb = new StringBuilder("From: a@example.com\r\n");
        for (int i = 0; i < 2500; i++) {
            sb.append("X-Trace: hop ").append(i).append("\r\n");
        }
        sb.append("\r\nbody\r\n");

        Message message = new Message(stream(sb));

        assertThat(message.getFields("X-Trace")).hasSize(2500);
    }

    @Test
    public void shouldParseLongFoldedField() throws Exception {
        StringBuilder sb = new StringBuilder("From: a@example.com\r\nTo: r0@example.com");
        for (int i = 1; i < 2000; i++) {
            sb.append(",\r\n r").append(i).append("@example.com");
        }
        sb.append("\r\n\r\nbody\r\n");

        Message message = new Message(stream(sb));

        assertThat(message.getFields("To")).hasSize(1);
    }

    @Test
    public void shouldParseLongLine() throws Exception {
        StringBuilder sb = new StringBuilder("From: a@example.com\r\nX-Long: ");
        for (int i = 0; i < 20000; i++) {
            sb.append('x');
        }
        sb.append("\r\n\r\nbody\r\n");

        Message message = new Message(stream(sb));

        assertThat(message.getFields("X-Long")).hasSize(1);
    }

    @Test
    public void signerShouldSignMessagesWithManyHeaderFields() throws Exception {
        StringBuilder sb = new StringBuilder("From: a@messiah.edu\r\n");
        for (int i = 0; i < 2500; i++) {
            sb.append("Received: hop ").append(i).append("\r\n");
        }
        sb.append("\r\nbody\r\n");

        String field = new DKIMSigner("v=1; a=rsa-sha256; c=simple; d=messiah.edu; h=from; s=selector2;", TestKeys.privateKey)
                .sign(stream(sb));

        assertThat(field).startsWith("DKIM-Signature:");
    }

    private static StringBuilder longTo(int recipients) {
        StringBuilder sb = new StringBuilder("From: a@messiah.edu\r\nTo: r0@example.com");
        for (int i = 1; i < recipients; i++) {
            sb.append(",\r\n r").append(i).append("@example.com");
        }
        return sb.append("\r\n\r\nbody\r\n");
    }

    @Test
    public void shouldParseFoldedFieldLongerThan64K() throws Exception {
        // about 90 KB unfolded
        Message message = new Message(stream(longTo(5000)));

        assertThat(message.getFields("To")).hasSize(1);
    }

    @Test
    public void signerShouldSignMessageWithFoldedFieldLongerThan64K() throws Exception {
        String field = new DKIMSigner("v=1; a=rsa-sha256; c=simple; d=messiah.edu; h=from:to; s=selector2;", TestKeys.privateKey)
                .sign(stream(longTo(5000)));

        assertThat(field).startsWith("DKIM-Signature:");
    }

    @Test
    public void shouldParseMoreThan4096HeaderFields() throws Exception {
        StringBuilder sb = new StringBuilder("From: a@example.com\r\n");
        for (int i = 0; i < 6000; i++) {
            sb.append("Received: hop ").append(i).append("\r\n");
        }
        sb.append("\r\nbody\r\n");

        Message message = new Message(stream(sb));

        assertThat(message.getFields("Received")).hasSize(6000);
    }

    @Test
    public void headerOverOneMegabyteShouldBeRejected() {
        // about 1.6 MB unfolded
        assertThatThrownBy(() -> new Message(stream(longTo(100000))))
                .isInstanceOf(MimeException.class)
                .hasMessageContaining("limit");
    }
}
