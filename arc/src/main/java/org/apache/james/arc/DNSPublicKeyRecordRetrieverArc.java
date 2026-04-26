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
package org.apache.james.arc;

import org.apache.james.dmarc.DNSPublicKeyRecordRetrieverDmarc;
import org.apache.james.dmarc.PublicKeyRecordRetrieverDmarc;
import org.apache.james.jdkim.impl.DNSPublicKeyRecordRetriever;
import org.apache.james.jspf.impl.DefaultSPF;
import org.apache.james.jspf.impl.SPF;

public class DNSPublicKeyRecordRetrieverArc extends DNSPublicKeyRecordRetriever implements PublicKeyRetrieverArc {
    public static final DNSPublicKeyRecordRetrieverDmarc DMARC = new DNSPublicKeyRecordRetrieverDmarc();

    public DNSPublicKeyRecordRetrieverArc() {
        super();
    }

    @Override
    public String getSpfRecord(String helo, String from, String ip) {
        SPF spf = new DefaultSPF();
        return spf.checkSPF(ip, from, helo).getHeaderText();
    }

    @Override
    public PublicKeyRecordRetrieverDmarc getDmarcRetriever() {
        return DMARC;
    }
}
