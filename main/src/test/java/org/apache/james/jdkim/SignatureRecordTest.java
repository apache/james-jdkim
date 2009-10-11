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

import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.tagvalue.SignatureRecordImpl;

import junit.framework.TestCase;

public class SignatureRecordTest extends TestCase {

    public void testBasic() {
        SignatureRecord sign = new SignatureRecordImpl(
                "v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n"
                        + "        d=gmail.com; s=beta;\r\n"
                        + "        h=domainkey-signature:received:received:message-id:date:from:to:subject:mime-version:content-type;\r\n"
                        + "        bh=9sd6eO/xnGLInYGPFN86r9q27iClGpwfkl4PBc5XEuQ=;\r\n"
                        + "        b=tGQtBQg1sO+JKopOylApWLngylEqeMcXwCEUQN+S2PSpi9c1G9Nm5df9pMShus3iFaQb0PPvTfpw++cAC8/N0p3Gi/lVLc+Yh7xWEIPZ3Nxd3xqTQy7grIkBpV0q6559dEhhfFoEyLS0OK/IrqFIUVDRIMnsMjimXV7u+Sgoi7Q=");
        sign.validate();
    }

    public void testWrongOrMissingVersion() {
        try {
            SignatureRecord sign = new SignatureRecordImpl(
                    "a=rsa-sha1; c=relaxed/relaxed;\r\n"
                            + "        d=gmail.com; s=beta;\r\n"
                            + "        h=domainkey-signature:received:received:message-id:date:from:to:subject:mime-version:content-type;\r\n"
                            + "        b=Kw/TqnjB4L5ZC7DX1ibiNkuIw630uHZvzuozn/e6yTm3U8ObWEz/rJK5GO8RSrF56JrCA/xo8W2CGmyNmpQYbEpLl5P9/NcJSYUmln/O6GSa4Usyv4FdEU4FVjkyW0ToGFHNkw9Mm0urveA4Lcfk9gClJczXnvGBdiv/bkVBEJk=");
            sign.validate();
            fail("expected error on missing v=");
        } catch (IllegalStateException e) {
        }
        try {
            SignatureRecord sign = new SignatureRecordImpl(
                    "v=2; a=rsa-sha256; c=relaxed/relaxed;\r\n"
                            + "        d=gmail.com; s=beta;\r\n"
                            + "        h=domainkey-signature:received:received:message-id:date:from:to:subject:mime-version:content-type;\r\n"
                            + "        bh=9sd6eO/xnGLInYGPFN86r9q27iClGpwfkl4PBc5XEuQ=;\r\n"
                            + "        b=tGQtBQg1sO+JKopOylApWLngylEqeMcXwCEUQN+S2PSpi9c1G9Nm5df9pMShus3iFaQb0PPvTfpw++cAC8/N0p3Gi/lVLc+Yh7xWEIPZ3Nxd3xqTQy7grIkBpV0q6559dEhhfFoEyLS0OK/IrqFIUVDRIMnsMjimXV7u+Sgoi7Q=");
            sign.validate();
            fail("expected error on wrong v=");
        } catch (IllegalStateException e) {
        }
    }

    public void testMissingRequired() {
        try {
            SignatureRecord sign = new SignatureRecordImpl(
                    "v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n"
                            + "        d=gmail.com; s=beta;\r\n"
                            + "        h=domainkey-signature:received:received:message-id:date:from:to:subject:mime-version:content-type;\r\n"
                            + "        b=tGQtBQg1sO+JKopOylApWLngylEqeMcXwCEUQN+S2PSpi9c1G9Nm5df9pMShus3iFaQb0PPvTfpw++cAC8/N0p3Gi/lVLc+Yh7xWEIPZ3Nxd3xqTQy7grIkBpV0q6559dEhhfFoEyLS0OK/IrqFIUVDRIMnsMjimXV7u+Sgoi7Q=");
            sign.validate();
            fail("expected error on missing bh=");
        } catch (IllegalStateException e) {
        }
    }

    public void testDomainMismatch() {
        try {
            SignatureRecord sign = new SignatureRecordImpl(
                    "v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n"
                            + "        d=gmail.com; s=beta; i=@agmail.com;\r\n"
                            + "        h=domainkey-signature:received:received:message-id:date:from:to:subject:mime-version:content-type;\r\n"
                            + "        bh=9sd6eO/xnGLInYGPFN86r9q27iClGpwfkl4PBc5XEuQ=;\r\n"
                            + "        b=tGQtBQg1sO+JKopOylApWLngylEqeMcXwCEUQN+S2PSpi9c1G9Nm5df9pMShus3iFaQb0PPvTfpw++cAC8/N0p3Gi/lVLc+Yh7xWEIPZ3Nxd3xqTQy7grIkBpV0q6559dEhhfFoEyLS0OK/IrqFIUVDRIMnsMjimXV7u+Sgoi7Q=");
            sign.validate();
            fail("expected error on domain mismatch");
        } catch (IllegalStateException e) {
        }
    }

    public void testMissingFrom() {
        try {
            SignatureRecord sign = new SignatureRecordImpl(
                    "v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n"
                            + "        d=gmail.com; s=beta; i=@subdomain.gmail.com;\r\n"
                            + "        h=domainkey-signature:received:received:message-id:date:fram:to:subject:mime-version:content-type;\r\n"
                            + "        bh=9sd6eO/xnGLInYGPFN86r9q27iClGpwfkl4PBc5XEuQ=;\r\n"
                            + "        b=tGQtBQg1sO+JKopOylApWLngylEqeMcXwCEUQN+S2PSpi9c1G9Nm5df9pMShus3iFaQb0PPvTfpw++cAC8/N0p3Gi/lVLc+Yh7xWEIPZ3Nxd3xqTQy7grIkBpV0q6559dEhhfFoEyLS0OK/IrqFIUVDRIMnsMjimXV7u+Sgoi7Q=");
            sign.validate();
            fail("expected error on missing 'from' header");
        } catch (IllegalStateException e) {
        }
    }

}
