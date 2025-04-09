/******************************************************************************
 * Licensed to the Apache Software Foundation (ASF) under one                 *
 * or more contributor license agreements.  See the NOTICE file               *
 * distributed with this work for additional information                      *
 * regarding copyright ownership.  The ASF licenses this file                 *
 * to you under the Apache License, Version 2.0 (the                          *
 * "License"); you may not use this file except in compliance                 *
 * with the License.  You may obtain a copy of the License at                 *
 *                                                                            *
 *   http://www.apache.org/licenses/LICENSE-2.0                               *
 *                                                                            *
 * Unless required by applicable law or agreed to in writing,                 *
 * software distributed under the License is distributed on an                *
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY                     *
 * KIND, either express or implied.  See the License for the                  *
 * specific language governing permissions and limitations                    *
 * under the License.                                                         *
 ******************************************************************************/

package org.apache.james.jdkim.api;

import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;

public enum HashMethod {
    /**
     * SHA-1 is specified standard RFC 6376 [1].
     * However, in january 2018, RFC 8301 [1] was proposed which states that
     * SHA-1 it MUST NOT be used any more.
     * While RFC 8301 is not an internet standard, the reasons it lists for
     * dropping SHA-1 (security implications because hash collision) apply
     * today
     * [1] https://datatracker.ietf.org/doc/html/rfc6376
     * [2] https://datatracker.ietf.org/doc/html/rfc8301
     *
     * @deprecated prefer using SHA256 hashing, see javadoc for details.
      */

    @Deprecated()
    SHA1{
        @Override
        public String asMessageDigestAlgorithm() {
            return "SHA-1";
        }
    },

    SHA256{
        @Override
        public String asMessageDigestAlgorithm() {
            return "SHA-256";
        }
    },

    ;

    public String asTagValue() {
        return this.name().toLowerCase(Locale.ROOT);
    }
    public abstract String asMessageDigestAlgorithm();

    public static Optional<HashMethod> of(String methodName){
        return Arrays.stream(values())
                .filter(m-> m.name().toLowerCase(Locale.ROOT).equals(methodName.toLowerCase(Locale.ROOT)))
                .findFirst();
    }
}