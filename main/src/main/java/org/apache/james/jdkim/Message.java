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

import org.apache.james.mime4j.MimeException;
import org.apache.james.mime4j.MimeIOException;
import org.apache.james.mime4j.io.EOLConvertingInputStream;
import org.apache.james.mime4j.parser.Field;
import org.apache.james.mime4j.parser.MimeEntityConfig;
import org.apache.james.mime4j.parser.MimeTokenStream;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * The header of an entity (see RFC 2045).
 * 
 * TODO: we have to handle correct ordered extraction for fields.
 */
public class Message implements Iterable, Headers {

	private List fields = new LinkedList();
	private Map fieldMap = new HashMap();
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
	 *            the stream to read the header from.
	 * 
	 * @throws IOException
	 *             on I/O errors.
	 * @throws MimeIOException
	 *             on MIME protocol violations.
	 */
	public Message(InputStream is) throws IOException, MimeException {
		MimeEntityConfig mec = new MimeEntityConfig();
		mec.setMaxLineLen(10000);
		MimeTokenStream stream = new ExtendedMimeTokenStream(mec);
		stream.setRecursionMode(MimeTokenStream.M_FLAT);
		// DKIM requires no isolated CR or LF, so we alter them at source.
		stream.parse(new EOLConvertingInputStream(is));
		for (int state = stream.getState(); state != MimeTokenStream.T_END_OF_STREAM; state = stream
				.next()) {
			switch (state) {
			// a field
			case MimeTokenStream.T_FIELD:
				addField(stream.getField());
				break;

			// expected ignored tokens
			case MimeTokenStream.T_START_MESSAGE:
			case MimeTokenStream.T_END_MESSAGE:
			case MimeTokenStream.T_START_HEADER:
			case MimeTokenStream.T_END_HEADER:
				break;

			// the body stream
			case MimeTokenStream.T_BODY:
				this.bodyIs = stream.getInputStream();
				break;

			default:
				throw new IllegalStateException("Unexpected stream message: "
						+ state);
			}
			// stop parsing after header
			if (bodyIs != null)
				break;
		}

	}

	public InputStream getBodyInputStream() {
		return bodyIs;
	}

	public void setBodyInputStream(InputStream is) {
		bodyIs = is;
	}

	/**
	 * Adds a field to the end of the list of fields.
	 * 
	 * @param field
	 *            the field to add.
	 */
	public void addField(Field field) {
		List values = (List) fieldMap.get(field.getName().toLowerCase());
		if (values == null) {
			values = new LinkedList();
			fieldMap.put(field.getName().toLowerCase(), values);
		}
		values.add(new String(field.getRaw().toByteArray()));
		fields.add(new String(field.getRaw().toByteArray()));
	}

	/* (non-Javadoc)
	 * @see org.apache.james.jdkim.Headers#getFields()
	 */
	public List getFields() {
		return Collections.unmodifiableList(fields);
	}

	/* (non-Javadoc)
	 * @see org.apache.james.jdkim.Headers#getField(java.lang.String)
	 */
	public String getField(String name) {
		List l = (List) fieldMap.get(name.toLowerCase());
		if (l != null && !l.isEmpty()) {
			return (String) l.get(0);
		}
		return null;
	}

	/* (non-Javadoc)
	 * @see org.apache.james.jdkim.Headers#getFields(java.lang.String)
	 */
	public List getFields(final String name) {
		final String lowerCaseName = name.toLowerCase();
		final List l = (List) fieldMap.get(lowerCaseName);
		final List results;
		if (l == null || l.isEmpty()) {
			results = Collections.emptyList();
		} else {
			results = Collections.unmodifiableList(l);
		}
		return results;
	}

	/**
	 * Returns an iterator over the list of fields of this header.
	 * 
	 * @return an iterator.
	 */
	public Iterator iterator() {
		return Collections.unmodifiableList(fields).iterator();
	}


	/**
	 * Return Header Object as String representation. Each headerline is
	 * seperated by "\r\n"
	 * 
	 * @return headers
	 */
	public String toString() {
		StringBuffer str = new StringBuffer(128);
		for (Iterator i = fields.iterator(); i.hasNext();) {
			String field = (String) i.next();
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

	/**
	 * Extends this to publish the constructor
	 */
	private final class ExtendedMimeTokenStream extends MimeTokenStream {

		public ExtendedMimeTokenStream(MimeEntityConfig mec) {
			super(mec);
		}
	}

}