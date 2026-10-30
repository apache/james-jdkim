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

package org.apache.james.jdkim.impl;

import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Records the bytes of the header block (up to the empty line that ends it)
 * while they are read, so that the header fields can be taken from the raw
 * bytes instead of from the fields the MIME parser kept.
 * <p>
 * Expects CRLF line endings.
 */
class HeaderCapturingInputStream extends FilterInputStream {

    private final ByteArrayOutputStream header = new ByteArrayOutputStream();
    // number of bytes of the "\r\n\r\n" terminator seen so far
    private int matched = 2;
    private boolean complete;

    HeaderCapturingInputStream(InputStream in) {
        super(in);
    }

    @Override
    public int read() throws IOException {
        int b = super.read();
        if (b != -1) {
            capture((byte) b);
        }
        return b;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int read = super.read(b, off, len);
        for (int i = 0; i < read && !complete; i++) {
            capture(b[off + i]);
        }
        return read;
    }

    @Override
    public long skip(long n) throws IOException {
        // read the skipped bytes so that none of the header is missed
        byte[] buffer = new byte[(int) Math.min(n, 2048)];
        int read = read(buffer, 0, buffer.length);
        return Math.max(read, 0);
    }

    @Override
    public boolean markSupported() {
        return false;
    }

    private void capture(byte b) {
        if (complete) {
            return;
        }
        header.write(b);
        // the header block starts right after a (virtual) CRLF
        if (b == "\r\n\r\n".charAt(matched)) {
            matched++;
        } else {
            matched = b == '\r' ? 1 : 0;
        }
        if (matched == 4) {
            complete = true;
        }
    }

    /**
     * @return the header block read so far, the terminating empty line included
     */
    byte[] getHeader() {
        return header.toByteArray();
    }
}
