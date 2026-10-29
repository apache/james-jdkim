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

import org.apache.james.jdkim.impl.DNSPublicKeyRecordRetriever;
import org.apache.james.jdkim.impl.MultiplexingPublicKeyRecordRetriever;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Resolver;

import java.time.Duration;

public class VerifierOptions {
    /**
     * System property holding the default of {@link Builder#withMaxSignatures(int)}.
     */
    public static final String MAX_SIGNATURE_COUNT_PROPERTY = "james.dkim.max-signature.count";
    private static final int DEFAULT_MAX_SIGNATURE_COUNT = 32;

    private final Duration clockDriftTolerance;
    private final int maxSignatures;
    private final PublicKeyRecordRetriever publicKeyRecordRetriever;
    private final Resolver dnsResolver;

    public static class Builder {
        private Duration clockDriftTolerance = Duration.ofSeconds(300);
        private int maxSignatures = Integer.getInteger(MAX_SIGNATURE_COUNT_PROPERTY, DEFAULT_MAX_SIGNATURE_COUNT);
        private Resolver dnsResolver = Lookup.getDefaultResolver();
        private PublicKeyRecordRetriever publicKeyRecordRetriever = new MultiplexingPublicKeyRecordRetriever(
                "dns", new DNSPublicKeyRecordRetriever(this.dnsResolver));

        /**
         * Sets the clock drift tolerance for signature verification, default is 300 seconds.
         *
         * @param clockDriftTolerance a {@link Duration}
         * @return {@link Builder}
         */
        public Builder withClockDriftTolerance(Duration clockDriftTolerance) {
            this.clockDriftTolerance = clockDriftTolerance;
            return this;
        }

        /**
         * Sets a custom PublicKeyRecordRetriever, a default is used if not set.
         *
         * @param publicKeyRecordRetriever a {@link PublicKeyRecordRetriever}
         * @return {@link Builder}
         */
        public Builder withPublicKeyRecordRetriever(PublicKeyRecordRetriever publicKeyRecordRetriever) {
            this.publicKeyRecordRetriever = publicKeyRecordRetriever;
            return this;
        }

        /**
         * Sets the maximum number of DKIM-Signature fields verified per message, as allowed by RFC 6376 section 6.1.
         * The fields beyond it are reported as PERMERROR, without key lookup. Defaults to the
         * {@value #MAX_SIGNATURE_COUNT_PROPERTY} system property, or 32.
         *
         * @param maxSignatures a strictly positive number of signatures
         * @return {@link Builder}
         */
        public Builder withMaxSignatures(int maxSignatures) {
            this.maxSignatures = maxSignatures;
            return this;
        }

        /**
         * A custom dns resolver
         *
         * @param dnsResolver a {@link Resolver}
         * @return {@link Builder}
         */
        public Builder withDnsResolver(Resolver dnsResolver) {
            this.dnsResolver = dnsResolver;
            return this;
        }

        public VerifierOptions build() {
            return new VerifierOptions(this);
        }
    }

    private VerifierOptions(Builder builder) {
        if (builder.clockDriftTolerance == null) {
            throw new IllegalArgumentException("clockDriftTolerance can not be null");
        }
        if (builder.clockDriftTolerance.isNegative()) {
            throw new IllegalArgumentException("clockDriftTolerance must not be negative");
        }

        if (builder.maxSignatures <= 0) {
            throw new IllegalArgumentException("maxSignatures must be strictly positive");
        }

        if (builder.publicKeyRecordRetriever == null) {
            throw new IllegalArgumentException("publicKeyRecordRetriever can not be null");
        }

        if (builder.dnsResolver == null) {
            throw new IllegalArgumentException("dnsResolver can not be null");
        }

        this.clockDriftTolerance = builder.clockDriftTolerance;
        this.maxSignatures = builder.maxSignatures;
        this.dnsResolver = builder.dnsResolver;
        this.publicKeyRecordRetriever = builder.publicKeyRecordRetriever;
    }

    /**
     * Gets current clock drift tolerance used for signature verification
     *
     * @return {@link Duration}
     */
    public Duration getClockDriftTolerance() {
        return clockDriftTolerance;
    }

    /**
     * Gets the maximum number of DKIM-Signature fields verified per message
     *
     * @return the maximum number of signatures
     */
    public int getMaxSignatures() {
        return maxSignatures;
    }

    /**
     * Gets current PublicKeyRecordRetriever instance
     *
     * @return {@link PublicKeyRecordRetriever}
     */
    public PublicKeyRecordRetriever getPublicKeyRecordRetriever() {
        return publicKeyRecordRetriever;
    }

    /**
     * Gets current dns resolver
     *
     * @return {@link Resolver}
     */
    public Resolver getDnsResolver() {
        return dnsResolver;
    }
}
