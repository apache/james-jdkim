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

    public RelaxedBodyCanonicalizer(OutputStream out) {
        super(new SimpleBodyCanonicalizer(out));
        pendingSpaces = false;
    }

    public void write(byte[] buffer, int off, int len) throws IOException {
        int start = off;
        int end = len + off;
        for (int k = off; k < end; k++) {
            if (pendingSpaces) {
                if (buffer[k] != ' ' && buffer[k] != '\t') {
                    if (buffer[k] != '\r')
                        out.write(' ');
                    pendingSpaces = false;
                    len = len - k + start;
                    start = k;
                }
            } else {
                if (buffer[k] == ' ' || buffer[k] == '\t') {
                    if (k + 1 < end && buffer[k] == ' ' && buffer[k + 1] != ' '
                            && buffer[k + 1] != '\t' && buffer[k + 1] != '\r') {
                        // optimization: we skip single spaces
                        // make sure we optimize only when we are on a space.
                    } else {
                        // compute everything from start to end;
                        out.write(buffer, start, k - start);
                        pendingSpaces = true;
                    }
                }
            }
        }
        if (!pendingSpaces) {
            out.write(buffer, start, len);
        }
    }

    public void write(int b) throws IOException {
        if (pendingSpaces) {
            if (b != ' ' && b != '\t') {
                if (b != '\r')
                    out.write(' ');
                pendingSpaces = false;
                out.write(b);
            }
        } else {
            if (b == ' ' || b == '\t') {
                pendingSpaces = true;
            } else {
                out.write(b);
            }
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
        if (pendingSpaces)
            out.write(' ');
    }

}