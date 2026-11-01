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
 * Implements Relaxed canonicalization for the body as defined in RFC4871 -
 * 3.4.4. The "relaxed" Body Canonicalization Algorithm
 */
public class RelaxedBodyCanonicalizer extends FilterOutputStream {

    private boolean pendingSpaces;
    // a CR was read: WSP before it is dropped only if it ends the line
    private boolean pendingCR;

    public RelaxedBodyCanonicalizer(OutputStream out) {
        super(new SimpleBodyCanonicalizer(out, true));
        pendingSpaces = false;
    }

    public void write(byte[] buffer, int off, int len) throws IOException {
        int end = off + len;
        int k = off;
        while (k < end) {
            if (pendingSpaces || pendingCR) {
                write(buffer[k]);
                k++;
                continue;
            }
            // nothing is pending: copy everything up to the next WSP or CR as is
            int next = k;
            while (next < end && buffer[next] != ' ' && buffer[next] != '\t' && buffer[next] != '\r') {
                next++;
            }
            if (next == k) {
                write(buffer[k]);
                k++;
            } else {
                out.write(buffer, k, next - k);
                k = next;
            }
        }
    }

    public void write(int b) throws IOException {
        // OutputStream#write(int): the 24 high-order bits are ignored
        b &= 0xFF;
        if (pendingCR) {
            pendingCR = false;
            if (b == '\n') {
                // whitespace at the end of a line is ignored
                pendingSpaces = false;
                out.write('\r');
                out.write('\n');
                return;
            }
            // a lone CR does not end the line
            flushSpaces();
            out.write('\r');
        }
        if (b == ' ' || b == '\t') {
            pendingSpaces = true;
        } else if (b == '\r') {
            pendingCR = true;
        } else {
            flushSpaces();
            out.write(b);
        }
    }

    public void close() throws IOException {
        complete();
        super.close();
    }

    /**
     * Called internally to make sure we output the buffered whitespace if any.
     */
    private void complete() throws IOException {
        flushSpaces();
        if (pendingCR) {
            pendingCR = false;
            out.write('\r');
        }
    }

    private void flushSpaces() throws IOException {
        if (pendingSpaces) {
            out.write(' ');
            pendingSpaces = false;
        }
    }

}