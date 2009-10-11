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

    public final static String RELAXED = "relaxed";
    public final static String SIMPLE = "simple";
    public final static String ALL = ";all;";

    public abstract List/* CharSequence */getHeaders();

    public abstract CharSequence getIdentityLocalPart();

    public abstract CharSequence getIdentity();

    public abstract CharSequence getHashKeyType();

    public abstract CharSequence getHashMethod();

    public abstract CharSequence getHashAlgo();

    public abstract CharSequence getSelector();

    public abstract CharSequence getDToken();

    public abstract byte[] getBodyHash();

    public abstract int getBodyHashLimit();

    public abstract String getHeaderCanonicalisationMethod();

    public abstract String getBodyCanonicalisationMethod();

    public abstract List getRecordLookupMethods();

    public abstract void validate();

    public abstract byte[] getSignature();
    
    public abstract void setSignature(byte[] newSignature);
    
    public abstract void setBodyHash(byte[] newBodyHash);
    
    public abstract String toUnsignedString();

}