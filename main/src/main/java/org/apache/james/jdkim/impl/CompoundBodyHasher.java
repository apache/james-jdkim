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

package org.apache.james.jdkim.impl;

import java.io.OutputStream;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.james.jdkim.api.BodyHasher;
import org.apache.james.jdkim.canon.CompoundOutputStream;
import org.apache.james.jdkim.exceptions.FailException;

/**
 * CompoundBodyHasher is used for verification purpose.
 * 
 * It contains a compund output stream that will calculate
 * the body hash for multiple signatures.
 * 
 * This object is a container for "bodyHashJobs" and 
 * "signatureExceptions" for 2-stage verification process.
 */
public class CompoundBodyHasher implements BodyHasher {

    private final OutputStream o;
    private final Map<String, BodyHasherImpl> bodyHashJobs;
    private final Map<String, FailException> signatureExceptions;
    
    public CompoundBodyHasher(Map<String, BodyHasherImpl> bodyHashJobs,
            Hashtable<String, FailException> signatureExceptions) {
        this.bodyHashJobs = bodyHashJobs;
        this.signatureExceptions = signatureExceptions;
        if (bodyHashJobs.size() == 1) {
            o = ((BodyHasherImpl) bodyHashJobs.values().iterator().next())
                    .getOutputStream();
        } else {
            List<OutputStream> outputStreams = new LinkedList<OutputStream>();
            for (BodyHasherImpl bhj : bodyHashJobs.values()) {
                outputStreams.add(bhj.getOutputStream());
            }
            o = new CompoundOutputStream(outputStreams);
        }
    }

    public OutputStream getOutputStream() {
        return o;
    }
    
    public Map<String, BodyHasherImpl> getBodyHashJobs() {
        return bodyHashJobs;
    }

    public Map<String, FailException> getSignatureExceptions() {
        return signatureExceptions;
    }

}
