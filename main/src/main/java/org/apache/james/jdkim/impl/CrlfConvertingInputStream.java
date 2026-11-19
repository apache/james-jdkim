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

import java.io.IOException;
import java.io.InputStream;

/**
 * Converts a lone CR and a lone LF to CRLF, as mime4j's EOLConvertingInputStream with CONVERT_BOTH does, but
 * a block at a time: that stream only implements read(), so every bulk read went through one virtual call
 * chain per octet.
 */
class CrlfConvertingInputStream extends InputStream {

    private final InputStream in;
    private final byte[] buffer = new byte[8192];
    private int position;
    private int limit;
    // the previous octet of the source was a CR, already written as CRLF: an LF right after it is dropped
    private boolean afterCR;
    // the LF of a CRLF that did not fit in the caller's array
    private boolean pendingLF;

    CrlfConvertingInputStream(InputStream in) {
        this.in = in;
    }

    @Override
    public int read() throws IOException {
        byte[] one = new byte[1];
        int read = read(one, 0, 1);
        return read == -1 ? -1 : one[0] & 0xFF;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (off < 0 || len < 0 || len > b.length - off) {
            throw new IndexOutOfBoundsException();
        }
        if (len == 0) {
            return 0;
        }
        int o = off;
        int end = off + len;
        if (pendingLF) {
            pendingLF = false;
            b[o++] = '\n';
        }
        while (o < end) {
            if (position == limit) {
                // read the source again only if nothing is returned yet, so that a read never blocks needlessly
                if (o > off || !fill()) {
                    break;
                }
            }
            byte c = buffer[position++];
            if (c == '\r') {
                afterCR = true;
                b[o++] = '\r';
                if (o < end) {
                    b[o++] = '\n';
                } else {
                    pendingLF = true;
                }
            } else if (c == '\n') {
                if (afterCR) {
                    afterCR = false;
                    continue;
                }
                b[o++] = '\r';
                if (o < end) {
                    b[o++] = '\n';
                } else {
                    pendingLF = true;
                }
            } else {
                afterCR = false;
                b[o++] = c;
            }
        }
        return o == off ? -1 : o - off;
    }

    private boolean fill() throws IOException {
        int read;
        do {
            read = in.read(buffer, 0, buffer.length);
        } while (read == 0);
        if (read == -1) {
            return false;
        }
        position = 0;
        limit = read;
        return true;
    }

    @Override
    public void close() throws IOException {
        in.close();
    }
}
