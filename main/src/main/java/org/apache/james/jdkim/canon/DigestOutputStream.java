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
import java.security.MessageDigest;

/**
 * DigestOutputStream is used as a filter stream or as the ending stream in
 * order to calculate a digest of a stream.
 */
public class DigestOutputStream extends FilterOutputStream {

    private MessageDigest md;

    public DigestOutputStream(MessageDigest md) {
        this(md, null);
    }

    public DigestOutputStream(MessageDigest md, OutputStream out) {
        super(out);
        this.md = md;
    }

    public void write(int arg0) throws IOException {
        md.update((byte) arg0);
        if (out != null)
            out.write(arg0);
    }

    public void write(byte[] b, int off, int len) throws IOException {
        md.update(b, off, len);
        if (out != null)
            out.write(b, off, len);
    }

    public void close() throws IOException {
        if (out != null)
            super.close();
    }

    public void flush() throws IOException {
        if (out != null)
            super.flush();
    }

    public void write(byte[] b) throws IOException {
        md.update(b);
        if (out != null)
            out.write(b);
    }

    /**
     * @return the stream digest as a byte array
     */
    public byte[] getDigest() {
        return md.digest();
    }

}