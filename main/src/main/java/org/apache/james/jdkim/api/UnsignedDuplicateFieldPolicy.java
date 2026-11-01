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

/**
 * What the verifier does with a signature when the message holds more instances of a single-instance
 * field (such as From:) than the signature's h= tag lists, so that at least one of them is not signed.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6376#section-8.15">RFC 6376 section 8.15</a>
 */
public enum UnsignedDuplicateFieldPolicy {
    /**
     * The signature is evaluated as usual: an unsigned extra instance does not change its result.
     */
    ACCEPT,
    /**
     * The signature keeps its PASS result, which carries a warning (see {@link Result#getWarning()}).
     */
    FLAG,
    /**
     * The signature fails.
     */
    REJECT
}
