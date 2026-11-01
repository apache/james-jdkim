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
import java.util.LinkedList;
import java.util.List;

import org.apache.james.jdkim.api.BodyHasher;
import org.apache.james.jdkim.canon.CompoundOutputStream;
import org.apache.james.jdkim.exceptions.FailException;

/**
 * CompoundBodyHasher is used for verification purpose.
 * It contains a compund output stream that will calculate
 * the body hash for multiple signatures.
 * This object is a container for one {@link Job} per DKIM-Signature field,
 * in field order, for 2-stage verification process.
 */
public class CompoundBodyHasher implements BodyHasher {

    /**
     * The verification state of one DKIM-Signature field: either a body hasher
     * still to be checked, or the failure that ended its verification.
     */
    public static class Job {
        private final String signatureField;
        private BodyHasherImpl bodyHasher;
        private FailException failure;
        private String warning;

        public Job(String signatureField) {
            this.signatureField = signatureField;
        }

        public String getSignatureField() {
            return signatureField;
        }

        public BodyHasherImpl getBodyHasher() {
            return bodyHasher;
        }

        public void setBodyHasher(BodyHasherImpl bodyHasher) {
            this.bodyHasher = bodyHasher;
        }

        public FailException getFailure() {
            return failure;
        }

        /**
         * @return the warning to attach to the result of a successful verification, or null
         */
        public String getWarning() {
            return warning;
        }

        public void setWarning(String warning) {
            this.warning = warning;
        }

        public void setFailure(FailException failure) {
            this.failure = failure;
            this.bodyHasher = null;
        }
    }

    private final OutputStream o;
    private final List<Job> jobs;

    public CompoundBodyHasher(List<Job> jobs) {
        this.jobs = jobs;
        List<OutputStream> outputStreams = new LinkedList<>();
        for (Job job : jobs) {
            if (job.getBodyHasher() != null) {
                outputStreams.add(job.getBodyHasher().getOutputStream());
            }
        }
        if (outputStreams.size() == 1) {
            o = outputStreams.get(0);
        } else {
            o = new CompoundOutputStream(outputStreams);
        }
    }

    public OutputStream getOutputStream() {
        return o;
    }

    public List<Job> getJobs() {
        return jobs;
    }

}
