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

package org.apache.james.jdkim.api;

import java.util.List;

/**
 * Raw header fields of a message, as used for DKIM header canonicalization.
 * <p>
 * Each returned field is the raw field (name, colon and value, folding
 * included, without the trailing CRLF) where every char is one octet of the
 * message, as decoded with ISO-8859-1. Implementations must not decode the
 * field with any other charset: canonicalization works on the raw octets
 * (RFC 6376 section 3.4) and a lossy decoding would let signed bytes be
 * altered without breaking the signature.
 */
public interface Headers {

    /**
     * Gets the fields of this header. The returned list will not be modifiable.
     * 
     * @return the list of <code>Field</code> objects.
     */
    List<String> getFields();

    /**
     * Gets all <code>Field</code>s having the specified field name in a case
     * insensitive way.
     * 
     * @param name
     *                the field name (e.g. From, Subject).
     * @return the list of fields.
     */
    List<String> getFields(final String name);

}