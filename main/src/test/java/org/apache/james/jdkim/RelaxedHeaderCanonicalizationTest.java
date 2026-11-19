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

package org.apache.james.jdkim;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.Random;

import org.junit.Test;

public class RelaxedHeaderCanonicalizationTest {

    /**
     * The former implementation, with "\\z" where it had "$": "$" also matches before a final line terminator,
     * so it deleted a space that RFC 6376 section 3.4.2 keeps ("a \r\n" ends with CRLF, not with WSP).
     */
    private static String reference(String fv) {
        String headerValue = fv.substring(fv.indexOf(':') + 1);
        headerValue = headerValue.replaceAll("\r\n[\t ]", " ");
        headerValue = headerValue.replaceAll("[\t ]+", " ");
        return headerValue.replaceAll("^ | \\z", "");
    }

    private static String canonical(String fv) {
        return new String(DKIMCommon.relaxedValue(fv), StandardCharsets.ISO_8859_1);
    }

    @Test
    public void shouldGiveTheRfc6376Examples() {
        assertThat(canonical("A: X")).isEqualTo("X");
        assertThat(canonical("B : Y\t\r\n\tZ  ")).isEqualTo("Y Z");
        assertThat(canonical("c:")).isEqualTo("");
        assertThat(canonical("d: \t ")).isEqualTo("");
    }

    @Test
    public void shouldKeepControlCharactersAroundTheValue() {
        assertThat(canonical("a:\u0001 x \u0001")).isEqualTo("\u0001 x \u0001");
        assertThat(canonical("a: \r\nx")).isEqualTo("\r\nx");
        assertThat(canonical("a:x \r\n")).isEqualTo("x \r\n");
    }

    @Test
    public void shouldUnfoldOnlyCrlfFollowedByWsp() {
        assertThat(canonical("a: x\r\n\r\n y")).isEqualTo("x\r\n y");
        assertThat(canonical("a: x\r\n\t\r\n y")).isEqualTo("x y");
        assertThat(canonical("a: x\ry\nz")).isEqualTo("x\ry\nz");
    }

    @Test
    public void shouldRejectCharsAboveU00ff() {
        String fv = "a: x" + (char) 0x100;
        assertThatThrownBy(() -> DKIMCommon.relaxedValue(fv))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("above U+00FF");
    }

    @Test
    public void shouldMatchTheRegexImplementationOnRandomFields() {
        char[] alphabet = {' ', '\t', '\r', '\n', 'a', ':', (char) 0x01, (char) 0xe9, (char) 0x85};
        Random random = new Random(6376);
        for (int run = 0; run < 200000; run++) {
            StringBuilder sb = new StringBuilder();
            int length = random.nextInt(12);
            for (int i = 0; i < length; i++) {
                sb.append(alphabet[random.nextInt(alphabet.length)]);
            }
            String fv = "x:" + sb;
            assertThat(canonical(fv)).as("field [%s]", fv).isEqualTo(reference(fv));
        }
    }
}
