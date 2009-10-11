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
        for (int i = 0; i < testData.length; i++) {
            os.write(testData[i]);
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
}
