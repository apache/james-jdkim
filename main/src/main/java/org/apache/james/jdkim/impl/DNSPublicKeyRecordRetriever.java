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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.apache.james.jdkim.api.PublicKeyRecordRetriever;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.exceptions.TempFailException;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

public class DNSPublicKeyRecordRetriever implements PublicKeyRecordRetriever {

    // The resolver used for the lookup
    protected Resolver resolver;

    public DNSPublicKeyRecordRetriever() {
        this(Lookup.getDefaultResolver());
    }

    public DNSPublicKeyRecordRetriever(Resolver resolver) {
        this.resolver = resolver;
    }

    /**
     * @see org.apache.james.jdkim.api.PublicKeyRecordRetriever#getRecords(java.lang.CharSequence, java.lang.CharSequence, java.lang.CharSequence)
     */
    public List<String> getRecords(CharSequence methodAndOptions,
            CharSequence selector, CharSequence token)
            throws TempFailException, PermFailException {
        if (!"dns/txt".equals(methodAndOptions))
            throw new PermFailException("Only dns/txt is supported: "
                    + methodAndOptions + " options unsupported.");
        try {
            Lookup query = new Lookup(selector + "._domainkey." + token,
                    Type.TXT);
            query.setResolver(resolver);

            Record[] rr = query.run();
            int queryResult = query.getResult();

            if (queryResult == Lookup.TRY_AGAIN) {
                throw new TempFailException(query.getErrorString());
            }

            List<String> records = convertRecordsToList(rr);
            return records;
        } catch (TextParseException e) {
            // TODO log
            return null;
        }
    }

    /**
     * Convert the given TXT Record array to a String List
     * 
     * @param rr
     *                Record array
     * @return list
     */
    @SuppressWarnings("unchecked")
    public static List<String> convertRecordsToList(Record[] rr) {
        List<String> records;
        if (rr != null && rr.length > 0) {
            records = new ArrayList<String>();
            for (int i = 0; i < rr.length; i++) {
                switch (rr[i].getType()) {
                case Type.TXT:
                    TXTRecord txt = (TXTRecord) rr[i];
                    if (txt.getStrings().size() == 1) {
                        // This was required until dnsjava 2.0.6 because dnsjava
                        // was escaping
                        // the result like it was doublequoted (JDKIM-7).
                        // records.add(((String)txt.getStrings().get(0)).replaceAll("\\\\",
                        // ""));
                        records.add(((String) txt.getStrings().get(0)));
                    } else {
                        StringBuilder sb = new StringBuilder();
                        for (Iterator<String> it = txt.getStrings()
                                .iterator(); it.hasNext();) {
                            String k = it.next();
                            // This was required until dnsjava 2.0.6 because
                            // dnsjava was escaping
                            // the result like it was doublequoted (JDKIM-7).
                            // k = k.replaceAll("\\\\", "");
                            sb.append(k);
                        }
                        records.add(sb.toString());
                    }
                    break;
                default:
                    return null;
                }
            }
        } else {
            records = null;
        }
        return records;
    }

}
