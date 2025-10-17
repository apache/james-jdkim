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
package org.apache.james.dmarc;

import org.apache.james.dmarc.exceptions.DmarcException;
import org.apache.james.jdkim.MockPublicKeyRecordRetriever;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.exceptions.TempFailException;

import java.util.List;

public class MockPublicKeyRecordRetrieverDmarc extends MockPublicKeyRecordRetriever implements PublicKeyRecordRetrieverDmarc {
    public static final String DMARC = "_dmarc.";

    @Override
    public String getDmarcRecord(String query) {
        try {
            List<String> recs = super.getRecords("dns/txt", DMARC, query);
            if (recs == null || recs.isEmpty()) {
                return null;
            }
            return recs.get(0);
        } catch (TempFailException e) {
            throw new DmarcException("Temporary failure looking up DMARC record", e);
        } catch (PermFailException e) {
            throw new DmarcException("Permanent failure looking up DMARC record", e);
        }
    }

    @Override
    public List<String> getRecords(CharSequence methodAndOption, CharSequence selector, CharSequence token) throws TempFailException, PermFailException {
        return List.of();
    }

    public static class DmarcRecord extends  MockPublicKeyRecordRetriever.Record {

        public DmarcRecord(String domain, String dmarcRecord) {
            super(DMARC, domain, dmarcRecord);
        }

        public static DmarcRecord dmarcOf(String domain, String dmarcRecord) {
            return new DmarcRecord(domain, dmarcRecord);
        }
    }

    public MockPublicKeyRecordRetrieverDmarc(Record... records) {
        super(records);
    }
}
