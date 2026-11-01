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

import org.apache.james.jdkim.api.Headers;
import org.apache.james.mime4j.MimeException;
import org.apache.james.mime4j.MimeIOException;
import org.apache.james.mime4j.dom.MessageBuilder;
import org.apache.james.mime4j.dom.MessageServiceFactory;
import org.apache.james.mime4j.dom.SingleBody;
import org.apache.james.mime4j.io.EOLConvertingInputStream;
import org.apache.james.mime4j.stream.MimeConfig;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The header of an entity (see RFC 2045).
 */
public class Message implements Headers {

    private final org.apache.james.mime4j.dom.Message message;
    private final List<String> fields;
    private final Map<String, List<String>> fieldsByName;

    /**
     * Creates a new <code>Header</code> from the specified stream.
     *
     * @param is the stream to read the header from.
     * @throws IOException     on I/O errors.
     * @throws MimeException  on MIME protocol violations, or when a parsing limit is exceeded.
     */
    public Message(InputStream is) throws IOException, MimeException {
        MessageBuilder mb = newMessageBuilder().newMessageBuilder();

        // mime4j drops the fields whose name it cannot parse and normalizes the
        // others: the fields are taken from the raw header bytes instead.
        HeaderCapturingInputStream header = new HeaderCapturingInputStream(new EOLConvertingInputStream(is));
        try {
            this.message = mb.parseMessage(header);
        } catch (MimeIOException e) {
            // a parsing limit or a MIME violation, not an I/O error: callers report it as a permanent error
            throw e.getCause() != null ? e.getCause() : new MimeException(e);
        }

        List<String> all = splitFields(new String(header.getHeader(), StandardCharsets.ISO_8859_1));
        Map<String, List<String>> byName = new HashMap<>();
        for (String field : all) {
            byName.computeIfAbsent(rawName(field), name -> new ArrayList<>()).add(field);
        }
        byName.replaceAll((name, list) -> Collections.unmodifiableList(list));
        this.fields = Collections.unmodifiableList(all);
        this.fieldsByName = byName;
    }

    private MessageServiceFactory newMessageBuilder() throws MimeException {
        // the limits of mime4j's permissive profile (4096 fields, 64 KB per field, no line limit) are well
        // above what real mail uses; the next mime4j release makes them configurable with the
        // james.mime4j.permissive.* system properties
        MimeConfig mec = MimeConfig.PERMISSIVE;

        MessageServiceFactory mbf = MessageServiceFactory.newInstance();
        mbf.setAttribute("MimeEntityConfig", mec);
        mbf.setAttribute("FlatMode", true);
        mbf.setAttribute("ContentDecoding", false);

        return mbf;
    }

    /**
     * Splits a CRLF-terminated header block into raw fields: a line starting
     * with WSP continues the previous field.
     *
     * @throws MimeException on a line that is neither a field nor a
     *                       continuation: DKIM cannot vouch for a header block
     *                       it does not see whole.
     */
    private static List<String> splitFields(String header) throws MimeException {
        List<String> all = new ArrayList<>();
        StringBuilder current = null;
        int start = 0;
        while (start < header.length()) {
            int end = header.indexOf("\r\n", start);
            if (end == -1) {
                end = header.length();
            }
            String line = header.substring(start, end);
            start = end + 2;
            if (line.isEmpty()) {
                // end of the header block
                break;
            }
            if (current != null && (line.charAt(0) == ' ' || line.charAt(0) == '\t')) {
                current.append("\r\n").append(line);
                continue;
            }
            addField(all, current);
            current = new StringBuilder(line);
        }
        addField(all, current);
        return all;
    }

    private static void addField(List<String> all, StringBuilder field) throws MimeException {
        if (field == null) {
            return;
        }
        if (field.indexOf(":") == -1 || field.charAt(0) == ' ' || field.charAt(0) == '\t') {
            throw new MimeException("Malformed header field: " + field);
        }
        all.add(field.toString());
    }

    /**
     * The name DKIM matches against h= is the raw text before the colon,
     * without trailing WSP.
     */
    private static String rawName(String field) {
        return field.substring(0, field.indexOf(':')).replaceAll("[ \t]+$", "").toLowerCase(Locale.US);
    }

    public InputStream getBodyInputStream() {
        try {
            return ((SingleBody) message.getBody()).getInputStream();
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * @see org.apache.james.jdkim.api.Headers#getFields()
     */
    public List<String> getFields() {
        return fields;
    }

    /**
     * @see org.apache.james.jdkim.api.Headers#getFields(java.lang.String)
     */
    public List<String> getFields(final String name) {
        return fieldsByName.getOrDefault(name.toLowerCase(Locale.US), Collections.emptyList());
    }

    /**
     * Return Header Object as String representation. Each headerline is
     * seperated by "\r\n"
     *
     * @return headers
     */
    public String toString() {
        return message.toString();
    }

    /**
     * Make sure to dispose the message once used.
     */
    public void dispose() {
        this.message.dispose();
    }
}
