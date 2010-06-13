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
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

public class CompoundOutputStreamTest extends AbstractOutputStreamTestCase {

    private byte[] testData;

    protected void setUp() throws Exception {
        testData = new byte[4096];
        for (int i = 0; i < testData.length; i++) {
            testData[i] = (byte) ((i * i * 4095 + (testData.length - i) * 17) % 128);
        }
    }

    public void testSingleBytes() throws NoSuchAlgorithmException, IOException {
        List<ByteArrayOutputStream> oss = new LinkedList<ByteArrayOutputStream>();
        for (int i = 0; i < 5; i++) {
            oss.add(new ByteArrayOutputStream());
        }
        CompoundOutputStream os = new CompoundOutputStream(oss);
        for (int i = 0; i < testData.length; i++) {
            os.write(testData[i]);
        }
        os.close();
        for (Iterator<ByteArrayOutputStream> i = oss.iterator(); i.hasNext();) {
            ByteArrayOutputStream bos = i.next();
            assertArrayEquals(testData, bos.toByteArray());
        }
    }

    public void testChunks() throws NoSuchAlgorithmException, IOException {
        List<ByteArrayOutputStream> oss = new LinkedList<ByteArrayOutputStream>();
        for (int i = 0; i < 5; i++) {
            oss.add(new ByteArrayOutputStream());
        }
        CompoundOutputStream os = new CompoundOutputStream(oss);
        chunker(testData, os);
        for (Iterator<ByteArrayOutputStream> i = oss.iterator(); i.hasNext();) {
            ByteArrayOutputStream bos = i.next();
            assertArrayEquals(testData, bos.toByteArray());
        }
    }

}
