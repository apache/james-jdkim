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
 * Implements Simple canonicalization for the body as defined in RFC4871 -
 * 3.4.3. The "simple" Body Canonicalization Algorithm
 */
public class SimpleBodyCanonicalizer extends FilterOutputStream {

    private static final boolean DEEP_DEBUG = false;

    private final boolean emptyBodyIsEmpty;
    // a CR was read and the next byte tells whether it ends a line
    private boolean lastWasCR;
    // CRLFs read but not written yet: only the trailing ones are dropped
    private int countCRLF;
    private boolean hasContent;

    public SimpleBodyCanonicalizer(OutputStream arg0) {
        this(arg0, false);
    }

    /**
     * @param emptyBodyIsEmpty true to output nothing for a body made only of
     *                         CRLFs, as relaxed canonicalization requires (RFC
     *                         6376 section 3.4.4); simple outputs a single CRLF.
     */
    SimpleBodyCanonicalizer(OutputStream arg0, boolean emptyBodyIsEmpty) {
        super(arg0);
        this.emptyBodyIsEmpty = emptyBodyIsEmpty;
    }

    public void write(byte[] b, int off, int len) throws IOException {
        if (DEEP_DEBUG)
            System.out.println("I:(" + lastWasCR + "|" + countCRLF + ") ["
                    + new String(b, off, len) + "]");
        int end = off + len;
        int i = off;
        while (i < end) {
            if (lastWasCR || countCRLF > 0 || b[i] == '\r') {
                write(b[i]);
                i++;
                continue;
            }
            // nothing is pending: copy everything up to the next CR as is
            int next = i;
            while (next < end && b[next] != '\r') {
                next++;
            }
            out.write(b, i, next - i);
            hasContent = true;
            i = next;
        }
    }

    public void write(int b) throws IOException {
        // OutputStream#write(int): the 24 high-order bits are ignored
        b &= 0xFF;
        if (DEEP_DEBUG)
            System.out.println("B:(" + lastWasCR + "|" + countCRLF + ") [" + (char) b + "]");
        if (lastWasCR) {
            lastWasCR = false;
            if ('\n' == b) {
                countCRLF++;
                return;
            }
            // a lone CR is ordinary content (RFC 6376 section 3.4.3)
            writeContent('\r');
        }
        if ('\r' == b) {
            lastWasCR = true;
        } else {
            writeContent(b);
        }
    }

    public void close() throws IOException {
        complete();
        super.close();
    }

    private void complete() throws IOException {
        if (DEEP_DEBUG)
            System.out.println("C:(" + lastWasCR + "|" + countCRLF + ")");
        if (lastWasCR) {
            lastWasCR = false;
            writeContent('\r');
        }
        if (emptyBodyIsEmpty && !hasContent) {
            return;
        }
        out.write("\r\n".getBytes());
    }

    private void writeContent(int b) throws IOException {
        dumpCRLF();
        out.write(b);
        hasContent = true;
    }

    private void dumpCRLF() throws IOException {
        if (DEEP_DEBUG)
            System.out.println("D:(" + lastWasCR + "|" + countCRLF + ")");
        while (countCRLF > 0) {
            out.write("\r\n".getBytes());
            countCRLF--;
        }
    }

}