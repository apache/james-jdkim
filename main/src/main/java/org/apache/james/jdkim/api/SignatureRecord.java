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
 * A complete SignatureRecord, including the signature and "formatted".
 */
public interface SignatureRecord {

    String RELAXED = "relaxed";
    String SIMPLE = "simple";
    String ALL = ";all;";

    List<CharSequence> getHeaders();

    CharSequence getIdentityLocalPart();

    CharSequence getIdentity();

    CharSequence getHashKeyType();

    CharSequence getHashMethod();

    CharSequence getHashAlgo();

    CharSequence getSelector();

    CharSequence getDToken();

    byte[] getBodyHash();

    int getBodyHashLimit();

    String getHeaderCanonicalisationMethod();

    String getBodyCanonicalisationMethod();

    List<CharSequence> getRecordLookupMethods();

    void validate();

    byte[] getSignature();

    CharSequence getRawSignature();
    
    void setSignature(byte[] newSignature);
    
    void setBodyHash(byte[] newBodyHash);
    
    String toUnsignedString();

    Long getSignatureTimestamp();

}