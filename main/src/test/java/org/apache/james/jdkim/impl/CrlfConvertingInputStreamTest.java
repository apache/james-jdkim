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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Random;

import org.apache.james.mime4j.io.EOLConvertingInputStream;
import org.junit.Test;

public class CrlfConvertingInputStreamTest {

    private static final byte[] ALPHABET = {'\r', '\n', 'a', ' ', (byte) 0xff};

    /**
     * A source that returns at most a random number of octets per read, to move the block boundaries.
     */
    private static InputStream chopped(byte[] data, Random random) {
        return new ByteArrayInputStream(data) {
            @Override
            public synchronized int read(byte[] b, int off, int len) {
                return super.read(b, off, Math.min(len, 1 + random.nextInt(5)));
            }
        };
    }

    private static byte[] readAll(InputStream in, Random random) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] block = new byte[16];
        while (true) {
            int read;
            if (random.nextInt(4) == 0) {
                int b = in.read();
                if (b == -1) {
                    break;
                }
                out.write(b);
                continue;
            }
            read = in.read(block, 0, 1 + random.nextInt(block.length));
            if (read == -1) {
                break;
            }
            out.write(block, 0, read);
        }
        return out.toByteArray();
    }

    private static byte[] mime4j(byte[] data) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        InputStream in = new EOLConvertingInputStream(new ByteArrayInputStream(data));
        int b;
        while ((b = in.read()) != -1) {
            out.write(b);
        }
        return out.toByteArray();
    }

    @Test
    public void shouldConvertLikeEOLConvertingInputStream() throws IOException {
        Random random = new Random(5322);
        for (int run = 0; run < 50000; run++) {
            byte[] data = new byte[random.nextInt(40)];
            for (int i = 0; i < data.length; i++) {
                data[i] = ALPHABET[random.nextInt(ALPHABET.length)];
            }
            byte[] actual = readAll(new CrlfConvertingInputStream(chopped(data, random)), random);
            assertThat(actual).as("input %s", Arrays.toString(data)).isEqualTo(mime4j(data));
        }
    }

    @Test
    public void shouldCaptureTheHeaderWhateverTheBlocks() throws IOException {
        Random random = new Random(6376);
        for (int run = 0; run < 50000; run++) {
            byte[] data = new byte[random.nextInt(40)];
            for (int i = 0; i < data.length; i++) {
                data[i] = ALPHABET[random.nextInt(3)];
            }
            byte[] crlf = mime4j(data);
            HeaderCapturingInputStream header = new HeaderCapturingInputStream(chopped(crlf, random));
            assertThat(readAll(header, random)).isEqualTo(crlf);
            assertThat(header.getHeader()).as("input %s", Arrays.toString(crlf)).isEqualTo(headerBlock(crlf));
        }
    }

    // up to the first empty line, which may be the first line
    private static byte[] headerBlock(byte[] crlf) {
        byte[] prefixed = new byte[crlf.length + 2];
        prefixed[0] = '\r';
        prefixed[1] = '\n';
        System.arraycopy(crlf, 0, prefixed, 2, crlf.length);
        for (int i = 0; i + 4 <= prefixed.length; i++) {
            if (prefixed[i] == '\r' && prefixed[i + 1] == '\n' && prefixed[i + 2] == '\r' && prefixed[i + 3] == '\n') {
                return Arrays.copyOf(crlf, i + 2);
            }
        }
        return crlf;
    }
}
