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

package org.apache.james.jdkim.api;

import static org.assertj.core.api.Assertions.assertThat;

import org.apache.james.jdkim.tagvalue.SignatureRecordImpl;
import org.apache.james.jdkim.tagvalue.TagValue;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class ResultTest {

    // the records below carry sender-controlled d= and s= values that strict validation would reject
    @Before
    public void disableStrictValidation() {
        System.setProperty(TagValue.STRICT_VALIDATION_PROPERTY, "false");
    }

    @After
    public void restoreStrictValidation() {
        System.clearProperty(TagValue.STRICT_VALIDATION_PROPERTY);
    }

    @Test
    public void headerTextShouldKeepTokensUnquoted() {
        SignatureRecord record = new SignatureRecordImpl(
                "v=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=AAAA; b=keocS8z7y+utXXXX");
        Result result = new Result(record);

        assertThat(result.getHeaderTextWithReason())
                .isEqualTo("dkim=pass header.d=example.com header.s=sel header.b=keocS8z7y+ut reason=\"valid signature\"");
    }

    @Test
    public void headerTextShouldQuoteSenderValues() {
        SignatureRecord record = new SignatureRecordImpl(
                "v=1; a=rsa-sha256; d=example.com; s=s\"el; h=from; bh=AAAA; b=AA\"A");
        Result result = new Result("Invalid DKIM-Signature version (expected '1'): 1\" x=\"", "", record, Result.Type.FAIL);

        assertThat(result.getHeaderText()).isEqualTo("dkim=fail header.d=example.com header.s=\"s\\\"el\" header.b=\"AA\\\"A\"");
        assertThat(result.getHeaderTextWithReason()).endsWith("reason=\"Invalid DKIM-Signature version (expected '1'): 1\\\" x=\\\"\"");
    }

    @Test
    public void headerTextShouldQuoteEmptyValues() {
        SignatureRecord record = new SignatureRecordImpl("v=1; a=rsa-sha256; d=; s=; h=from; bh=AAAA; b=");
        Result result = new Result("error", "", record, Result.Type.FAIL);

        assertThat(result.getHeaderText()).isEqualTo("dkim=fail header.d=\"\" header.s=\"\" header.b=\"\"");
    }

    @Test
    public void headerTextShouldDropControlCharactersAndFolding() {
        // the tag-list parser rejects control characters: other SignatureRecord implementations may not
        SignatureRecord record = new SignatureRecordImpl(
                "v=1; a=rsa-sha256; d=x.example; s=sel; h=from; bh=AAAA; b=AAAA") {
            @Override
            public CharSequence getDToken() {
                return "(\u0001.example";
            }

            @Override
            public CharSequence getSelector() {
                return "se\r\n l\u007f";
            }

            @Override
            public CharSequence getRawSignature() {
                return "AAAA\r\n BBBB\r\n\tCCCC\u0001DDDD";
            }
        };
        Result result = new Result("bad \\ value\r\n \u007f\"", "", record, Result.Type.FAIL);

        assertThat(result.getHeaderTextWithReason()).isEqualTo(
                "dkim=fail header.d=\"(.example\" header.s=\"se l\" header.b=AAAABBBBCCCC reason=\"bad \\\\ value \\\"\"");
    }
}
