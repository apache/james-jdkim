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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.james.jdkim.api.PublicKeyRecordRetriever;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.exceptions.TempFailException;

public class MultiplexingPublicKeyRecordRetriever implements
        PublicKeyRecordRetriever {
    public static class Entry{
        String methodName;
        PublicKeyRecordRetriever retriever;

        private Entry(String methodName, PublicKeyRecordRetriever retriever) {
            this.methodName = methodName;
            this.retriever = retriever;
        }

        public static Entry of(String methodName, PublicKeyRecordRetriever retriever){
            return new Entry(methodName, retriever);
        }
    }
    private final Map<String, PublicKeyRecordRetriever> retrievers;

    private MultiplexingPublicKeyRecordRetriever() {
        retrievers = new HashMap<>();
    }

    public MultiplexingPublicKeyRecordRetriever(String methodName,
            PublicKeyRecordRetriever pkrr) {
        this();
        addRetriever(methodName, pkrr);
    }
    public MultiplexingPublicKeyRecordRetriever(Set<Entry> retrieverEntries) {
        this();
        retrieverEntries.forEach(it ->
                addRetriever(it.methodName, it.retriever)
        );
    }

    private void addRetriever(String methodName, PublicKeyRecordRetriever pkrr) {
        retrievers.put(methodName, pkrr);
    }

    public List<String> getRecords(CharSequence methodAndOption, CharSequence selector,
            CharSequence token) throws TempFailException, PermFailException {
        int pos = methodAndOption.toString().indexOf('/');
        String method = pos != -1 ? methodAndOption.subSequence(0, pos)
                .toString() : methodAndOption.toString();
        PublicKeyRecordRetriever pkrr = retrievers.get(method);
        if (pkrr != null) {
            return pkrr.getRecords(methodAndOption, selector, token);
        } else {
            throw new PermFailException(
                    "Unknown public key record retrieving method: "
                            + methodAndOption);
        }
    }

}