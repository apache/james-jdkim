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

package org.apache.james.jdkim;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import junit.framework.TestCase;

import org.apache.james.jdkim.impl.Message;
import org.apache.james.mime4j.MimeException;

public class MessageTest extends TestCase {

    public void testMessage() throws IOException, MimeException {
        String m = "";
        new Message(new ByteArrayInputStream(m.getBytes()));
    }

    public void testMessageInputStream() throws IOException, MimeException {
        String m = "Subject: test\r\n\r\nbody";
        new Message(new ByteArrayInputStream(m.getBytes()));
    }

    public void testGetBodyInputStream() throws IOException, MimeException {
        String text = "Subject: test\r\n\r\nbody";
        Message m = new Message(new ByteArrayInputStream(text.getBytes()));
        InputStream is = m.getBodyInputStream();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buff = new byte[200];
        int read;
        while ((read = is.read(buff)) > 0) {
            bos.write(buff, 0, read);
        }
        assertEquals("body", new String(bos.toByteArray()));
    }

    public void testAddField() throws MimeException {
        Message m = new Message();
        m.addField("Subject", "Subject: test\r\n");
        m.addField("Subject", "Subject: test2\r\n");
        List f = m.getFields("Subject");
        assertEquals(2, f.size());
        assertEquals("Subject: test\r\n", f.get(0));
        assertEquals("Subject: test2\r\n", f.get(1));
    }

    public void testGetFields() throws MimeException {
        Message m = new Message();
        m.addField("Subject", "Subject: test\r\n");
        m.addField("Subject", "Subject: test2\r\n");
        m.addField("From", "From: test2\r\n");
        List f = m.getFields();
        List expects = new LinkedList();
        expects.add("Subject: test\r\n");
        expects.add("Subject: test2\r\n");
        expects.add("From: test2\r\n");
        for (Iterator i = f.iterator(); i.hasNext();) {
            String field = (String) i.next();
            assertTrue(expects.remove(field));
        }
        assertEquals(0, expects.size());
    }

    /*
     * public void testGetField() throws MimeException, IOException { String
     * text = "Subject: test\r\n\r\nbody"; Headers m = new Message(new
     * ByteArrayInputStream(text.getBytes())); Field f = m.getField("Subject");
     * assertEquals(" test", f.getBody()); }
     */

    public void testGetFieldsString() throws MimeException {
        Message m = new Message();
        m.addField("Subject", "Subject: test\r\n");
        m.addField("subject", "subject: test2\r\n");
        m.addField("From", "From: test2\r\n");
        List f = m.getFields("Subject");
        List expects = new LinkedList();
        expects.add("Subject: test\r\n");
        expects.add("subject: test2\r\n");
        for (Iterator i = f.iterator(); i.hasNext();) {
            String field = (String) i.next();
            assertTrue(expects.remove(field));
        }
        assertEquals(0, expects.size());
    }

    public void testToString() throws MimeException {
        Message m = new Message();
        m.addField("Subject", "Subject: test\r\n");
        m.setBodyInputStream(new ByteArrayInputStream("body".getBytes()));
        String expected = "Subject: test\r\n\r\nbody";
        assertEquals(expected, m.toString());
    }

}
