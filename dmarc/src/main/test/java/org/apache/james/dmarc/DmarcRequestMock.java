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
import org.apache.james.jdkim.DKIMCommon;
import org.apache.james.mime4j.dom.Message;
import org.apache.james.mime4j.message.DefaultMessageBuilder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class DmarcRequestMock {
    private final Message _message;
    private final String _dkimResult;
    private final String _dkimDomain;
    private final String _spfResult;
    private final String _spfDomain;
    private final String _expectedResult;

    public DmarcRequestMock(String emailPath, String dkimResult, String dkimDomain, String spfResult, String spfDomain, String expectedResult) {
        _dkimResult = dkimResult;
        _dkimDomain = dkimDomain;
        _spfResult = spfResult;
        _spfDomain = spfDomain;
        _expectedResult = expectedResult;
        ByteArrayInputStream emailStream = null;
        try {
            emailStream = readFileToByteArrayInputStream(emailPath);
            DefaultMessageBuilder builder = new DefaultMessageBuilder();
            _message = builder.parseMessage(emailStream);
        } catch (URISyntaxException e) {
            throw new DmarcException("URI Syntax Exception when loading test email file", e);
        } catch (IOException e) {
            throw  new DmarcException("IOException when loading test email file", e);
        }
    }

   String dkimResult() {
        return _dkimResult;
    }

    String dkimDomain() {
        return _dkimDomain;
    }

    String spfResult() {
        return _spfResult;
    }

    String spfDomain() {
        return _spfDomain;
    }

    String expectedResult() {
        return _expectedResult;
    }

    Message message() {
        return _message;
    }

    private ByteArrayInputStream readFileToByteArrayInputStream(String fileName) throws URISyntaxException, IOException {
        URL resource = this.getClass().getResource(fileName);
        FileInputStream file = new FileInputStream(new File(resource.toURI()));
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        DKIMCommon.streamCopy(file, byteArrayOutputStream);
        String string = byteArrayOutputStream.toString();
        return new ByteArrayInputStream(string.getBytes(StandardCharsets.UTF_8));
    }

}
