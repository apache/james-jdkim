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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class DigestOutputStreamTest extends AbstractOutputStreamTestCase {

    private byte[] testData;
    private byte[] expectedDigest;

    protected void setUp() throws Exception {
        testData = new byte[4096];
        for (int i = 0; i < testData.length; i++) {
            testData[i] = (byte) ((i * i * 4095 + (testData.length - i) * 17) % 128);
        }
        MessageDigest md = MessageDigest.getInstance("sha-256");
        md.update(testData);
        expectedDigest = md.digest();
    }

    public void testSingleBytes() throws NoSuchAlgorithmException, IOException {
        DigestOutputStream dos = new DigestOutputStream(MessageDigest
                .getInstance("sha-256"));
        for (int i = 0; i < testData.length; i++) {
            dos.write(testData[i]);
        }
        dos.close();
        byte[] digest = dos.getDigest();
        assertTrue(Arrays.equals(expectedDigest, digest));
    }

    public void testChunks() throws NoSuchAlgorithmException, IOException {
        DigestOutputStream dos = new DigestOutputStream(MessageDigest
                .getInstance("sha-256"));
        chunker(testData, dos);
        byte[] digest = dos.getDigest();
        assertTrue(Arrays.equals(expectedDigest, digest));
    }

    public void testChunksAndPassthrough() throws NoSuchAlgorithmException,
            IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DigestOutputStream dos = new DigestOutputStream(MessageDigest
                .getInstance("sha-256"), bos);
        chunker(testData, dos);
        byte[] digest = dos.getDigest();
        assertTrue(Arrays.equals(expectedDigest, digest));
        assertTrue(Arrays.equals(testData, bos.toByteArray()));
    }
}
