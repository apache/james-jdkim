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

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Pass data to the underlying system until a given amount of bytes is reached.
 */
public class LimitedOutputStream extends FilterOutputStream {

    private int limit;
    private int computedBytes;

    /**
     * @param out
     *                an output stream that will receive the "trucated" stream.
     * @param limit
     *                a positive integer of the number of bytes to be passed to
     *                the underlying stream
     */
    public LimitedOutputStream(OutputStream out, int limit) {
        super(out);
        this.limit = limit;
        this.computedBytes = 0;
    }

    public void write(byte[] b, int off, int len) throws IOException {
        if (len > limit - computedBytes) {
            len = limit - computedBytes;
        }
        if (len > 0) {
            out.write(b, off, len);
            computedBytes += len;
        }
    }

    public void write(int b) throws IOException {
        if (computedBytes < limit) {
            out.write(b);
            computedBytes++;
        }
    }

    /**
     * @return the number of bytes passed to the underlying stream
     */
    public int getComputedBytes() {
        return computedBytes;
    }

    /**
     * @return true if the limit has been reached and no data is being passed to
     *         the underlying stream.
     */
    public boolean isLimited() {
        return computedBytes >= limit;
    }
}