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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

public class VerifierOptions {
    /**
     * System property holding the default of {@link Builder#withMaxSignatures(int)}.
     */
    public static final String MAX_SIGNATURE_COUNT_PROPERTY = "james.dkim.max-signature.count";
    private static final int DEFAULT_MAX_SIGNATURE_COUNT = 32;
    /**
     * System property holding the default of {@link Builder#withMinimumRsaKeyBits(int)}.
     */
    public static final String MIN_RSA_KEY_BITS_PROPERTY = "james.dkim.min-rsa-key-bits";
    private static final int DEFAULT_MIN_RSA_KEY_BITS = 1024;
    /**
     * System property holding the default of {@link Builder#withRsaSha1Allowed(boolean)}.
     */
    public static final String RSA_SHA1_ALLOWED_PROPERTY = "james.dkim.rsa-sha1.allowed";
    /**
     * System property holding the default of {@link Builder#withUnsignedDuplicateFieldPolicy(UnsignedDuplicateFieldPolicy)}.
     */
    public static final String UNSIGNED_DUPLICATE_FIELD_POLICY_PROPERTY = "james.dkim.unsigned-duplicate-field.policy";
    private static final UnsignedDuplicateFieldPolicy DEFAULT_UNSIGNED_DUPLICATE_FIELD_POLICY = UnsignedDuplicateFieldPolicy.REJECT;
    /**
     * Default of {@link Builder#withSingleInstanceFields(Collection)}: the fields RFC 5322 section 3.6 allows once.
     */
    public static final Set<String> DEFAULT_SINGLE_INSTANCE_FIELDS = Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(
            "from", "sender", "reply-to", "to", "cc", "bcc", "subject", "date", "message-id", "in-reply-to", "references")));

    private final Duration clockDriftTolerance;
    private final int maxSignatures;
    private final int minimumRsaKeyBits;
    private final boolean rsaSha1Allowed;
    private final UnsignedDuplicateFieldPolicy unsignedDuplicateFieldPolicy;
    private final Set<String> singleInstanceFields;
    private final PublicKeyRecordRetriever publicKeyRecordRetriever;
    private final Resolver dnsResolver;

    public static class Builder {
        private Duration clockDriftTolerance = Duration.ofSeconds(300);
        private int maxSignatures = Integer.getInteger(MAX_SIGNATURE_COUNT_PROPERTY, DEFAULT_MAX_SIGNATURE_COUNT);
        private int minimumRsaKeyBits = Integer.getInteger(MIN_RSA_KEY_BITS_PROPERTY, DEFAULT_MIN_RSA_KEY_BITS);
        private boolean rsaSha1Allowed = !"false".equalsIgnoreCase(System.getProperty(RSA_SHA1_ALLOWED_PROPERTY, "true").trim());
        private UnsignedDuplicateFieldPolicy unsignedDuplicateFieldPolicy = defaultUnsignedDuplicateFieldPolicy();
        private Set<String> singleInstanceFields = DEFAULT_SINGLE_INSTANCE_FIELDS;
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
         * Sets the minimum length, in bits, of the RSA keys whose signatures are accepted. Shorter keys get a
         * PERMERROR result. RFC 8301 section 3.2: signers MUST use keys of at least 1024 bits, and verifiers
         * MAY take the key length into account. Defaults to the {@value #MIN_RSA_KEY_BITS_PROPERTY} system
         * property, or 1024.
         *
         * @param minimumRsaKeyBits a positive number of bits, 0 to accept any key
         * @return {@link Builder}
         */
        public Builder withMinimumRsaKeyBits(int minimumRsaKeyBits) {
            this.minimumRsaKeyBits = minimumRsaKeyBits;
            return this;
        }

        /**
         * Sets whether a=rsa-sha1 signatures are accepted. RFC 8301 section 3.1: "rsa-sha1 MUST NOT be used
         * for signing or verifying", yet much legitimate mail is still signed with it. When refused, such
         * signatures get a PERMERROR result, without key lookup. Defaults to the
         * {@value #RSA_SHA1_ALLOWED_PROPERTY} system property, or true.
         *
         * @param rsaSha1Allowed false to follow RFC 8301
         * @return {@link Builder}
         */
        public Builder withRsaSha1Allowed(boolean rsaSha1Allowed) {
            this.rsaSha1Allowed = rsaSha1Allowed;
            return this;
        }

        /**
         * Sets what happens to a signature when the message holds more instances of a single-instance field
         * (see {@link #withSingleInstanceFields(Collection)}) listed in its h= tag than h= lists, and more than one
         * in total:
         * the extra instance is not signed, yet mail clients usually display the top-most one.
         * See RFC 6376 section 8.15. Signers protect themselves by listing the field once more in h=
         * than it appears ("h=from:from"). Defaults to the
         * {@value #UNSIGNED_DUPLICATE_FIELD_POLICY_PROPERTY} system property, or {@link UnsignedDuplicateFieldPolicy#REJECT}.
         *
         * @param unsignedDuplicateFieldPolicy an {@link UnsignedDuplicateFieldPolicy}
         * @return {@link Builder}
         */
        public Builder withUnsignedDuplicateFieldPolicy(UnsignedDuplicateFieldPolicy unsignedDuplicateFieldPolicy) {
            this.unsignedDuplicateFieldPolicy = unsignedDuplicateFieldPolicy;
            return this;
        }

        /**
         * Sets the names of the fields expected once per message, checked by
         * {@link #withUnsignedDuplicateFieldPolicy(UnsignedDuplicateFieldPolicy)}. Case-insensitive.
         * Defaults to the fields RFC 5322 section 3.6 allows once ({@link #DEFAULT_SINGLE_INSTANCE_FIELDS}).
         *
         * @param singleInstanceFields field names
         * @return {@link Builder}
         */
        public Builder withSingleInstanceFields(Collection<String> singleInstanceFields) {
            if (singleInstanceFields == null) {
                this.singleInstanceFields = null;
                return this;
            }
            Set<String> names = new LinkedHashSet<>();
            for (String name : singleInstanceFields) {
                if (name == null || name.trim().isEmpty()) {
                    throw new IllegalArgumentException("singleInstanceFields can not hold a blank name");
                }
                names.add(name.trim().toLowerCase(Locale.US));
            }
            this.singleInstanceFields = Collections.unmodifiableSet(names);
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

        if (builder.minimumRsaKeyBits < 0) {
            throw new IllegalArgumentException("minimumRsaKeyBits must not be negative");
        }

        if (builder.unsignedDuplicateFieldPolicy == null) {
            throw new IllegalArgumentException("unsignedDuplicateFieldPolicy can not be null");
        }

        if (builder.singleInstanceFields == null) {
            throw new IllegalArgumentException("singleInstanceFields can not be null");
        }

        if (builder.publicKeyRecordRetriever == null) {
            throw new IllegalArgumentException("publicKeyRecordRetriever can not be null");
        }

        if (builder.dnsResolver == null) {
            throw new IllegalArgumentException("dnsResolver can not be null");
        }

        this.clockDriftTolerance = builder.clockDriftTolerance;
        this.maxSignatures = builder.maxSignatures;
        this.minimumRsaKeyBits = builder.minimumRsaKeyBits;
        this.rsaSha1Allowed = builder.rsaSha1Allowed;
        this.unsignedDuplicateFieldPolicy = builder.unsignedDuplicateFieldPolicy;
        this.singleInstanceFields = builder.singleInstanceFields;
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
     * Gets the minimum length, in bits, of the RSA keys whose signatures are accepted
     *
     * @return a number of bits
     */
    public int getMinimumRsaKeyBits() {
        return minimumRsaKeyBits;
    }

    /**
     * Gets whether a=rsa-sha1 signatures are accepted
     *
     * @return true if they are
     */
    public boolean isRsaSha1Allowed() {
        return rsaSha1Allowed;
    }

    /**
     * Gets what happens to a signature leaving an instance of a single-instance field unsigned
     *
     * @return {@link UnsignedDuplicateFieldPolicy}
     */
    public UnsignedDuplicateFieldPolicy getUnsignedDuplicateFieldPolicy() {
        return unsignedDuplicateFieldPolicy;
    }

    /**
     * Gets the lower-cased names of the fields expected once per message
     *
     * @return field names
     */
    public Set<String> getSingleInstanceFields() {
        return singleInstanceFields;
    }

    private static UnsignedDuplicateFieldPolicy defaultUnsignedDuplicateFieldPolicy() {
        String value = System.getProperty(UNSIGNED_DUPLICATE_FIELD_POLICY_PROPERTY);
        if (value == null) {
            return DEFAULT_UNSIGNED_DUPLICATE_FIELD_POLICY;
        }
        try {
            return UnsignedDuplicateFieldPolicy.valueOf(value.trim().toUpperCase(Locale.US));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid " + UNSIGNED_DUPLICATE_FIELD_POLICY_PROPERTY + " value: " + value, e);
        }
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
