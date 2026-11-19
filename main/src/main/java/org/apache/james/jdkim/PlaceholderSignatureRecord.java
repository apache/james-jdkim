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

package org.apache.james.jdkim;

import java.util.List;

import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.tagvalue.SignatureRecordTemplate;

/**
 * The record of a result whose failure has no parsed signature (unparsable record, field past the
 * maxSignatures cap...). One instance is shared: its setters throw, and its getters return values that
 * cannot be changed through them.
 */
final class PlaceholderSignatureRecord implements SignatureRecord {

    static final SignatureRecord INSTANCE = new PlaceholderSignatureRecord();

    private final SignatureRecord placeholder = new SignatureRecordTemplate(
            "v=1; d=invalid; h=from; s=invalid; b=invalidsig") {
        @Override
        public void validate() {
            // placeholder for a failure without a parsed signature, not a record to check
        }
    };

    private PlaceholderSignatureRecord() {
        // computes the string representation now, so that the shared instance is never written to again
        placeholder.toString();
    }

    public List<CharSequence> getHeaders() {
        return placeholder.getHeaders();
    }

    public CharSequence getIdentityLocalPart() {
        return placeholder.getIdentityLocalPart();
    }

    public CharSequence getIdentity() {
        return placeholder.getIdentity();
    }

    public CharSequence getHashKeyType() {
        return placeholder.getHashKeyType();
    }

    public CharSequence getHashMethod() {
        return placeholder.getHashMethod();
    }

    public CharSequence getHashAlgo() {
        return placeholder.getHashAlgo();
    }

    public CharSequence getSelector() {
        return placeholder.getSelector();
    }

    public CharSequence getDToken() {
        return placeholder.getDToken();
    }

    public byte[] getBodyHash() {
        return placeholder.getBodyHash();
    }

    public int getBodyHashLimit() {
        return placeholder.getBodyHashLimit();
    }

    public String getHeaderCanonicalisationMethod() {
        return placeholder.getHeaderCanonicalisationMethod();
    }

    public String getBodyCanonicalisationMethod() {
        return placeholder.getBodyCanonicalisationMethod();
    }

    public List<CharSequence> getRecordLookupMethods() {
        return placeholder.getRecordLookupMethods();
    }

    public void validate() {
    }

    public byte[] getSignature() {
        return placeholder.getSignature();
    }

    public CharSequence getRawSignature() {
        return placeholder.getRawSignature();
    }

    public void setSignature(byte[] newSignature) {
        throw new UnsupportedOperationException("placeholder record");
    }

    public void setBodyHash(byte[] newBodyHash) {
        throw new UnsupportedOperationException("placeholder record");
    }

    public String toUnsignedString() {
        return placeholder.toUnsignedString();
    }

    public Long getSignatureTimestamp() {
        return placeholder.getSignatureTimestamp();
    }

    public String toString() {
        return placeholder.toString();
    }
}
