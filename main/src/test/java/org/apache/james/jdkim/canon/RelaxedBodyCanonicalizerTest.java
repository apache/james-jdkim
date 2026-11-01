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

package org.apache.james.jdkim.canon;

import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class RelaxedBodyCanonicalizerTest extends AbstractOutputStreamTestCase {

    private byte[] testData;
    private byte[] expectedData;

    protected void setUp() throws Exception {
        testData = "this  is a \r\n  canonicalization \ttest\r\n\r\n\r\n"
                .getBytes();
        expectedData = "this is a\r\n canonicalization test\r\n".getBytes();
    }

    public void testSingleBytes() throws NoSuchAlgorithmException, IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        RelaxedBodyCanonicalizer os = new RelaxedBodyCanonicalizer(bos);
        for (byte aTestData : testData) {
            os.write(aTestData);
        }
        os.close();
        assertArrayEquals(expectedData, bos.toByteArray());
    }

    public void testChunks() throws NoSuchAlgorithmException, IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        RelaxedBodyCanonicalizer os = new RelaxedBodyCanonicalizer(bos);
        chunker(testData, os);
        assertArrayEquals(expectedData, bos.toByteArray());
    }

    public void testEmptyAndBlankBodiesCanonicalizeToNothing() throws IOException {
        for (String body : new String[] {"", " \r\n", "\r\n\r\n", "\t \r\n \r\n"}) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            RelaxedBodyCanonicalizer os = new RelaxedBodyCanonicalizer(bos);
            os.write(body.getBytes());
            os.close();
            assertArrayEquals("[" + body + "]", new byte[0], bos.toByteArray());
        }
    }

    public void testNonEmptyBodyGetsAFinalCRLF() throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        RelaxedBodyCanonicalizer os = new RelaxedBodyCanonicalizer(bos);
        os.write("\r\nx".getBytes());
        os.close();
        assertArrayEquals("\r\nx\r\n".getBytes(), bos.toByteArray());
    }

    protected OutputStream newInstance(ByteArrayOutputStream bos) {
        return new RelaxedBodyCanonicalizer(bos);
    }

    public void testLoneCRDoesNotEndTheLine() throws IOException {
        extensiveChunker("\r".getBytes(), "\r\r\n".getBytes());
        extensiveChunker("a \t\rb\r\n".getBytes(), "a \rb\r\n".getBytes());
        extensiveChunker("\t\r\n \r \r\t".getBytes(), "\r\n \r \r \r\n".getBytes());
        extensiveChunker("a \r  \r\n".getBytes(), "a \r\r\n".getBytes());
    }

    public void testSingleBytesAndChunksAgree() throws IOException {
        byte[] body = "x  \r\r\n\r \t\r\ny\t".getBytes();
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        OutputStream os = newInstance(bytes);
        for (byte b : body) {
            os.write(b);
        }
        os.close();
        extensiveChunker(body, bytes.toByteArray());
    }

    public void testWriteIntIgnoresHighBits() throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        RelaxedBodyCanonicalizer os = new RelaxedBodyCanonicalizer(bos);
        for (byte b : "a  b\r\n".getBytes()) {
            os.write(b | 0x100); // OutputStream#write(int): the 24 high-order bits are ignored
        }
        os.close();
        assertArrayEquals("a b\r\n".getBytes(), bos.toByteArray());
    }
}
