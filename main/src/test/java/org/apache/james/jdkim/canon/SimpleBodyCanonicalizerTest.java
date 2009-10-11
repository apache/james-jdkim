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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;

public class SimpleBodyCanonicalizerTest extends AbstractOutputStreamTestCase {

    private byte[] testData;
    private byte[] expectedData;

    protected void setUp() throws Exception {
        testData = "this  is a \r\n  canonicalization \ttest\r\n\r\n\r\n"
                .getBytes();
        expectedData = "this  is a \r\n  canonicalization \ttest\r\n"
                .getBytes();
    }

    public void testSingleBytes() throws NoSuchAlgorithmException, IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        SimpleBodyCanonicalizer os = new SimpleBodyCanonicalizer(bos);
        for (int i = 0; i < testData.length; i++) {
            os.write(testData[i]);
        }
        os.close();
        assertArrayEquals(expectedData, bos.toByteArray());
    }

    public void testChunks() throws NoSuchAlgorithmException, IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        SimpleBodyCanonicalizer os = new SimpleBodyCanonicalizer(bos);
        chunker(testData, os);
        assertArrayEquals(expectedData, bos.toByteArray());
    }

    public void testCRLFchunk() throws NoSuchAlgorithmException, IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        SimpleBodyCanonicalizer os = new SimpleBodyCanonicalizer(bos);
        writeChunk(os, testData, 0, 37);
        // a buffer consisting of only CRLF was not handled correctly.
        // this test checks this.
        writeChunk(os, testData, 37, 6);
        os.close();
        assertArrayEquals(expectedData, bos.toByteArray());
    }

    public void testProblematicChunks() throws NoSuchAlgorithmException,
            IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        SimpleBodyCanonicalizer os = new SimpleBodyCanonicalizer(bos);
        writeChunk(os, testData, 0, 38);
        writeChunk(os, testData, 38, 2);
        // a buffer consisting of only LFCR after a previous chunk
        // ended with CR was not handled correctly.
        writeChunk(os, testData, 40, 3);
        os.close();
        assertArrayEquals(expectedData, bos.toByteArray());
    }

    protected OutputStream newInstance(ByteArrayOutputStream bos) {
        return new SimpleBodyCanonicalizer(bos);
    }

    public void testExtensiveChunks() throws NoSuchAlgorithmException,
            IOException {
        extensiveChunker(testData, expectedData);
    }

    public void testWrongCRSequences() throws NoSuchAlgorithmException,
            IOException {
        // byte[] test = "this is a \r\n canonica\rlizati\r\ron
        // \ttest\r\n\r\n\r\r".getBytes();
        // byte[] expected = "this is a \r\n canonica\rlizati\r\ron
        // \ttest\r\n\r\n\r\r\n".getBytes();
        byte[] test = "this  is a \r\n  canonica\rlizati".getBytes();
        byte[] expected = "this  is a \r\n  canonica\rlizati\r\n".getBytes();
        extensiveChunker(test, expected);
    }

    public void testProblematicCRSequences() throws NoSuchAlgorithmException,
            IOException {
        byte[] test = "this  is a \r\n  canonica\rlizati".getBytes();
        byte[] expected = "this  is a \r\n  canonica\rlizati\r\n".getBytes();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        SimpleBodyCanonicalizer os = new SimpleBodyCanonicalizer(bos);
        writeChunk(os, test, 0, 24);
        // this created a problem where a single byte write after a line
        // ending with \r was buggy
        writeChunk(os, test, 24, 1);
        writeChunk(os, test, 25, 5);
        os.close();
        assertArrayEquals(expected, bos.toByteArray());
    }

    public void testWrongCRSequencesAdv() throws NoSuchAlgorithmException,
            IOException {
        // byte[] test = "this is a \r\n canonica\rlizati\r\ron
        // \ttest\r\n\r\n\r\r".getBytes();
        // byte[] expected = "this is a \r\n canonica\rlizati\r\ron
        // \ttest\r\n\r\n\r\r\n".getBytes();
        byte[] test = "this  is a \r\n  canonica\rlizati\r\ron\r\n\r\n\r"
                .getBytes();
        byte[] expected = "this  is a \r\n  canonica\rlizati\r\ron\r\n"
                .getBytes();
        extensiveChunker(test, expected);
    }

    public void testProblematicEndingCRLFCR() throws NoSuchAlgorithmException,
            IOException {
        byte[] test = "this  is a \r\n  canonica\rlizati\r\ron\r\n\r\n\r"
                .getBytes();
        byte[] expected = "this  is a \r\n  canonica\rlizati\r\ron\r\n"
                .getBytes();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        SimpleBodyCanonicalizer os = new SimpleBodyCanonicalizer(bos);
        // checks a bug with an buffer ending with \r\n\r
        writeChunk(os, test, 0, 39);
        os.close();
        assertArrayEquals(expected, bos.toByteArray());
    }

    public void testProblematicEndingCR() throws NoSuchAlgorithmException,
            IOException {
        byte[] test = "this  is a \r\n  canonica\rlizati\r\ron\r\n\r\n\r"
                .getBytes();
        byte[] expected = "this  is a \r\n  canonica\rlizati\r\ron\r\n"
                .getBytes();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        SimpleBodyCanonicalizer os = new SimpleBodyCanonicalizer(bos);
        // checks a bug with an buffer ending with \r\n\r
        writeChunk(os, test, 0, 31);
        writeChunk(os, test, 31, 1);
        writeChunk(os, test, 32, 7);
        os.close();
        assertArrayEquals(expected, bos.toByteArray());
    }

}
