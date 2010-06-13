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

package org.apache.james.jdkim;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.james.jdkim.api.PublicKeyRecordRetriever;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.exceptions.TempFailException;

/**
 * This is a mock public key record retriever that store the "registry" in a
 * local map.
 */
public class MockPublicKeyRecordRetriever implements PublicKeyRecordRetriever {
    private static final String _DOMAINKEY = "._domainkey.";
    private Map<String, List<String>> records = new HashMap<String, List<String>>();

    public void addRecord(String selector, String token, String record) {
        String key = selector + _DOMAINKEY + token;
        List<String> l = records.get(key);
        if (l == null) {
            l = new LinkedList<String>();
            records.put(key, l);
        }
        if (record != null) {
            l.add(record);
        }
    }

    public MockPublicKeyRecordRetriever() {

    }

    public MockPublicKeyRecordRetriever(String record, CharSequence selector,
            CharSequence token) {
        addRecord(selector.toString(), token.toString(), record);
    }

    public List<String> getRecords(CharSequence methodAndOptions,
            CharSequence selector, CharSequence token)
            throws TempFailException, PermFailException {
        if ("dns/txt".equals(methodAndOptions)) {
            String search = selector + _DOMAINKEY + token;
            List<String> res = records.get(search);
            if (res == null || res.size() > 0)
                return res;
            else
                throw new TempFailException("Timout or servfail");
        } else
            throw new PermFailException("Unsupported method");
    }
}