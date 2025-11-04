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

import org.junit.Test;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class DMARCTest {

    private final MockPublicKeyRecordRetrieverDmarc recordRetrieverDmarc = new MockPublicKeyRecordRetrieverDmarc(
            MockPublicKeyRecordRetrieverDmarc.DmarcRecord.dmarcOf(
                    "d1.example",
                    "k=rsa; v=DMARC1; p=reject; pct=100; rua=mailto:noc@d1.example"),
            MockPublicKeyRecordRetrieverDmarc.DmarcRecord.dmarcOf(
                    "mail.replit.app",
                    "k=rsa; v=DMARC1; p=reject; aspf=r; adkim=r; pct=100; rua=mailto:noc@d1.example"),
            MockPublicKeyRecordRetrieverDmarc.DmarcRecord.dmarcOf(
                    "test.replit.app",
                    "k=rsa; v=DMARC1; p=reject; aspf=s; adkim=s; pct=100; rua=mailto:noc@d1.example")
    );

    private final List<DmarcRequestMock> passRequests = List.of(
            new DmarcRequestMock("/mail/e1.eml","pass", "d1.example", "softfail (spfCheck: transitioning domain of d1.example does not designate 222.222.222.222 as permitted sender) client-ip=222.222.222.222; envelope-from=jqd@d1.example; helo=d1.example", "d1.example", "dmarc=pass (p=reject) header.from=d1.example"),
            new DmarcRequestMock("/mail/e2.eml","pass", "mail.replit.app", "pass client-ip=222.222.222.222; envelope-from=jqd@id.firewalledreplit.co; helo=replit.app", "mail.replit.app", "dmarc=pass (p=reject) header.from=mail.replit.app"),
            new DmarcRequestMock("/mail/e3.eml","pass", "replit.app", "pass client-ip=222.222.222.222; envelope-from=jqd@id.firewalledreplit.co; helo=replit.app", "replit.app", "dmarc=fail (p=reject) header.from=test.replit.app")
            );

    DMARCVerifier dmarcVerifier = new DMARCVerifier(recordRetrieverDmarc);

    @Test
    public void generate_and_verify_dmarc_pass() {
        passRequests.forEach(r -> {
            assertThat(dmarcVerifier.runDmarcCheck(r.message(), r.spfResult(), r.spfDomain(), r.dkimResult(), r.dkimDomain()).toString()).hasToString(r.expectedResult());
        });
    }
}