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

    private boolean lastWasCR;
    private int countCRLF;

    public SimpleBodyCanonicalizer(OutputStream arg0) {
        super(arg0);
    }

    public void write(byte[] b, int off, int len) throws IOException {
        if (len <= 0)
            return;
        if (DEEP_DEBUG)
            System.out.println("I:(" + lastWasCR + "|" + countCRLF + ") ["
                    + new String(b, off, len) + "]");
        if (lastWasCR) {
            if (len > 0 && b[off] == '\n') {
                countCRLF++;
                lastWasCR = false;
                off++;
                len--;
            } else {
                // TODO output the lone \r ? (this condition should never happen
                // as we expect only CRLF in a compliant 7bit email.
                out.write('\r');
                lastWasCR = false;
            }
        }
        int newCountCRLF = 0;
        boolean newLastWasCR = false;
        if (len >= 1 && b[off + len - 1] == '\r') {
            newLastWasCR = true;
            len--;
        }
        while (len >= 2 && b[off + len - 1] == '\n' && b[off + len - 2] == '\r') {
            len -= 2;
            newCountCRLF++;
        }
        if (len > 0) {
            dumpCRLF();
            out.write(b, off, len);
        }
        countCRLF += newCountCRLF;
        lastWasCR = newLastWasCR;
    }

    public void write(int b) throws IOException {
        if (DEEP_DEBUG)
            System.out.println("B:(" + lastWasCR + "|" + countCRLF + ") ["
                    + new String("" + (char) b) + "]");
        if (lastWasCR && '\n' == b) {
            lastWasCR = false;
            countCRLF++;
        } else {
            if (!lastWasCR && '\r' == b) {
                lastWasCR = true;
            } else {
                dumpCRLF();
                if ('\r' == b)
                    lastWasCR = true;
                else
                    out.write(b);
            }
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
            // if the last char was a CR we'll let dumpCRLF
            // to output the missing \n
            lastWasCR = false;
        }
        countCRLF = 1;
        dumpCRLF();
    }

    private void dumpCRLF() throws IOException {
        if (DEEP_DEBUG)
            System.out.println("D:(" + lastWasCR + "|" + countCRLF + ")");
        if (lastWasCR) {
            out.write('\r');
            lastWasCR = false;
        }
        while (countCRLF > 0) {
            out.write("\r\n".getBytes());
            countCRLF--;
        }
    }

}