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
package org.apache.james.arc;

import org.apache.james.arc.exceptions.ArcException;
import org.apache.james.dmarc.MockPublicKeyRecordRetrieverDmarc;
import org.apache.james.jdkim.MockPublicKeyRecordRetriever;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.exceptions.TempFailException;

import java.util.List;

public class MockPublicKeyRecordRetrieverArc extends MockPublicKeyRecordRetriever implements PublicKeyRetrieverArc {

    public static final String SPF = "_spf.";
    private final MockPublicKeyRecordRetrieverDmarc _dmarcRetriever;

    public static class SpfRecord extends  MockPublicKeyRecordRetriever.Record {

        public SpfRecord(String helo, String from, String ip, String spfRecord) {
            super(SPF, ip + helo + from, spfRecord);
        }

        public static SpfRecord spfOf(String helo, String from, String ip, String spfRecord) {
            return new SpfRecord(helo, from, ip, spfRecord);
        }
    }

    public MockPublicKeyRecordRetrieverArc(MockPublicKeyRecordRetrieverDmarc dmarcRetriever, Record... records) {
        super(records);
        _dmarcRetriever = dmarcRetriever;
    }

    @Override
    public String getSpfRecord(String helo, String from, String ip) {
        try {
           String token = ip + helo + from;
                List<String> recs = super.getRecords("dns/txt", SPF,token);
                if (recs.isEmpty()) {
                    return null;
                }
                return recs.get(0);
        } catch (TempFailException e) {
            throw new ArcException("Temporary failure looking up DMARC record", e);
        } catch (PermFailException e) {
            throw new ArcException("Permanent failure looking up DMARC record", e);
        }
    }

    public MockPublicKeyRecordRetrieverDmarc getDmarcRetriever() {
        return _dmarcRetriever;
    }
}
