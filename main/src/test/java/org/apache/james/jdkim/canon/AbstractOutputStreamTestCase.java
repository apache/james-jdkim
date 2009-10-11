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

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import junit.framework.TestCase;

/**
 * Base class useful when testing outputstreams It simplify the job of testing
 * any weird chunking during the streamin.
 */
public abstract class AbstractOutputStreamTestCase extends TestCase {

    protected AbstractOutputStreamTestCase() {
    }

    public void chunker(BufferedInputStream is, OutputStream os)
            throws IOException {
        byte[] buffer = new byte[307];
        int read;
        int chunksCounter = 0; // 
        int bytesCounter = 0; // 
        while ((read = is.read(buffer, 0,
                (buffer.length / (chunksCounter % 8 + 1)))) > 0) {
            if (read == buffer.length && chunksCounter % 13 % 7 % 2 == 1) {
                os.write(buffer);
            } else if (chunksCounter % 11 != 0) {
                os.write(buffer, 0, read);
            } else
                for (int i = 0; i < read; i++) {
                    os.write(buffer[i]);
                }
            if (chunksCounter % 3 == 2)
                os.flush();
            chunksCounter++;
            bytesCounter += read;
        }
        os.close();
    }

    public void chunker(byte[] data, OutputStream os) throws IOException {
        BufferedInputStream is = new BufferedInputStream(
                new ByteArrayInputStream(data));
        chunker(is, os);
    }

    public void writeChunk(OutputStream os, byte[] data, int from, int len)
            throws IOException {
        if (len == 1)
            os.write(data[from]);
        else if (len == data.length)
            os.write(data);
        else
            os.write(data, from, len);
    }

    public void assertArrayEquals(String explanation, byte[] expected,
            byte[] actual) {
        if (!Arrays.equals(expected, actual)) {
            assertEquals(explanation, new String(expected), new String(actual));
        }
    }

    public void assertArrayEquals(byte[] expected, byte[] actual) {
        if (!Arrays.equals(expected, actual)) {
            assertEquals(new String(expected), new String(actual));
        }
    }

    protected OutputStream newInstance(ByteArrayOutputStream bos) {
        throw new IllegalStateException(
                "Implement newInstance in order to use extensive chunker");
    }

    /**
     * An extensive checker for streams. It split the buffer every possibile 1,
     * to and 3 part sequences and check the results.
     * 
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */
    public void extensiveChunker(byte[] data, byte[] expectedData)
            throws IOException {
        for (int i = 0; i < data.length; i++)
            for (int j = i; j < data.length; j++) {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                OutputStream os = newInstance(bos);

                writeChunk(os, data, 0, i);
                writeChunk(os, data, i, j - i);
                writeChunk(os, data, j, data.length - j);
                os.close();

                assertArrayEquals("i=" + i + ", j=" + j + ", l=" + data.length,
                        expectedData, bos.toByteArray());
            }
    }

}
