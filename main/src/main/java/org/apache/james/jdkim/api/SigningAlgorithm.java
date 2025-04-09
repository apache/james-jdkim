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

public enum SigningAlgorithm {
    RSA {
        @Override
        public String asJdkSignatureAlgorithm(HashMethod hashMethod) {
            return hashMethod.name() + "with" + name();
        }
    }, // RFC 6376 https://datatracker.ietf.org/doc/html/rfc6376#section-3.3
    ;

    public String asTagValue() {
        return this.name().toLowerCase(Locale.US);
    }

    public abstract String asJdkSignatureAlgorithm(HashMethod hashMethod);

    public static Optional<SigningAlgorithm> of(String signingAlgorithm) {
        return Arrays.stream(SigningAlgorithm.values())
                .filter(a -> a.name().toLowerCase(Locale.ROOT).equals(signingAlgorithm.toLowerCase(Locale.ROOT)))
                .findFirst();
    }
}
