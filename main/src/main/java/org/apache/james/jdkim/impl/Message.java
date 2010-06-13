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

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.james.jdkim.api.Headers;
import org.apache.james.mime4j.MimeException;
import org.apache.james.mime4j.io.EOLConvertingInputStream;
import org.apache.james.mime4j.parser.AbstractContentHandler;
import org.apache.james.mime4j.parser.MimeStreamParser;
import org.apache.james.mime4j.stream.BodyDescriptor;
import org.apache.james.mime4j.stream.MimeEntityConfig;
import org.apache.james.mime4j.stream.RawField;

/**
 * The header of an entity (see RFC 2045).
 */
public class Message extends AbstractContentHandler implements Headers {

    private List<String> fields = new LinkedList<String>();
    private Map<String, List<String>> fieldMap = new HashMap<String, List<String>>();
    private InputStream bodyIs = null;

    /**
     * Creates a new empty <code>Header</code>.
     */
    public Message() {
    }

    /**
     * Creates a new <code>Header</code> from the specified stream.
     * 
     * @param is
     *                the stream to read the header from.
     * 
     * @throws IOException
     *                 on I/O errors.
     * @throws MimeIOException
     *                 on MIME protocol violations.
     */
    public Message(InputStream is) throws IOException, MimeException {
        MimeEntityConfig mec = new MimeEntityConfig();
        mec.setMaxLineLen(10000);
        
        final MimeStreamParser parser = new MimeStreamParser(mec);
        parser.setFlat(true);
        parser.setContentDecoding(false);
        parser.setContentHandler(this);
        parser.parse(new EOLConvertingInputStream(is));
    }

    public InputStream getBodyInputStream() {
        return bodyIs;
    }

    public void field(RawField rawField) throws MimeException {
        addField(rawField.getName(), new String(rawField.getRaw().toByteArray()));
    }
    
    public void body(BodyDescriptor bd, InputStream is) throws MimeException,
            IOException {
        setBodyInputStream(is);
    }

    public void setBodyInputStream(InputStream is) {
        bodyIs = is;
    }

    /**
     * Adds a field to the end of the list of fields.
     * 
     * @param field
     *                the field to add.
     */
    public void addField(String fieldName, String field) {
        List<String> values = fieldMap.get(fieldName.toLowerCase());
        if (values == null) {
            values = new LinkedList<String>();
            fieldMap.put(fieldName.toLowerCase(), values);
        }
        values.add(field);
        fields.add(field);
    }

    /**
     * @see org.apache.james.jdkim.api.Headers#getFields()
     */
    public List<String> getFields() {
        return Collections.unmodifiableList(fields);
    }

    /**
     * @see org.apache.james.jdkim.api.Headers#getFields(java.lang.String)
     */
    public List<String> getFields(final String name) {
        final String lowerCaseName = name.toLowerCase();
        final List<String> l = fieldMap.get(lowerCaseName);
        final List<String> results;
        if (l == null || l.isEmpty()) {
            results = null;
        } else {
            results = Collections.unmodifiableList(l);
        }
        return results;
    }

    /**
     * Return Header Object as String representation. Each headerline is
     * seperated by "\r\n"
     * 
     * @return headers
     */
    public String toString() {
        StringBuffer str = new StringBuffer(128);
        for (Iterator<String> i = fields.iterator(); i.hasNext();) {
            String field = i.next();
            str.append(field);
        }
        InputStream is = getBodyInputStream();
        if (is != null) {
            str.append("\r\n");
            byte[] buff = new byte[128];
            int read;
            try {
                while ((read = is.read(buff)) > 0) {
                    str.append(new String(buff, 0, read));
                }
            } catch (IOException e) {
            }
        }
        return str.toString();
    }

}