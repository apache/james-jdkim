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

package org.apache.james.jdkim.canon;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Random;
import java.util.function.Function;

import org.junit.Test;

public class BodyCanonicalizerBlocksTest {

    private static final byte[] ALPHABET = {' ', '\t', '\r', '\n', 'a', 'b'};

    private static byte[] canonicalize(Function<OutputStream, OutputStream> canonicalizer, byte[] data,
                                       Random random) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        OutputStream os = canonicalizer.apply(bos);
        int i = 0;
        while (i < data.length) {
            if (random == null) {
                os.write(data[i++]);
                continue;
            }
            int len = Math.min(data.length - i, random.nextInt(9));
            if (len == 1) {
                os.write(data[i]);
            } else {
                os.write(data, i, len);
            }
            i += len;
        }
        os.close();
        return bos.toByteArray();
    }

    private static void assertBlocksGiveTheSameOctets(Function<OutputStream, OutputStream> canonicalizer)
            throws IOException {
        Random random = new Random(6376);
        for (int run = 0; run < 50000; run++) {
            byte[] data = new byte[run % 1000 == 0 ? 10000 : random.nextInt(30)];
            for (int i = 0; i < data.length; i++) {
                data[i] = ALPHABET[random.nextInt(ALPHABET.length)];
            }
            assertThat(canonicalize(canonicalizer, data, random)).as("input %s", Arrays.toString(data))
                    .isEqualTo(canonicalize(canonicalizer, data, null));
        }
    }

    @Test
    public void relaxedBlocksShouldGiveTheOctetsOfSingleBytes() throws IOException {
        assertBlocksGiveTheSameOctets(RelaxedBodyCanonicalizer::new);
    }

    @Test
    public void simpleBlocksShouldGiveTheOctetsOfSingleBytes() throws IOException {
        assertBlocksGiveTheSameOctets(SimpleBodyCanonicalizer::new);
    }
}
