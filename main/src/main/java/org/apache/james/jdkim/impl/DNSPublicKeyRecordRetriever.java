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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

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
    protected final Resolver resolver;

    public DNSPublicKeyRecordRetriever() {
        this(Lookup.getDefaultResolver());
    }

    public DNSPublicKeyRecordRetriever(Resolver resolver) {
        this.resolver = resolver;
    }

    /**
     * {@inheritDoc}
     */
    public List<String> getRecords(CharSequence methodAndOptions,
                                   CharSequence selector, CharSequence token)
            throws TempFailException, PermFailException {
        if (!"dns/txt".equals(methodAndOptions))
            throw new PermFailException("Only dns/txt is supported: "
                    + methodAndOptions + " options unsupported.");
        Lookup query;
        try {
            query = new Lookup(selector + "._domainkey." + token, Type.TXT);
        } catch (TextParseException e) {
            throw new PermFailException("Invalid dns record", e);
        }
        query.setResolver(resolver);

        Record[] rr = query.run();

        if (query.getResult() == Lookup.TRY_AGAIN) {
            throw new TempFailException(query.getErrorString());
        }

        if (rr == null || rr.length == 0) {
            return Collections.emptyList();
        }

        return Arrays.stream(rr)
                .filter(r -> r.getType() == Type.TXT)
                .map(r -> String.join("", ((TXTRecord) r).getStrings()))
                .collect(Collectors.toList());
    }
}
