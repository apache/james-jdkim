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

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.apache.james.jdkim.api.Result;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.exceptions.FailException;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;

/**
 * Creates a TestSuite running the test for each .msg file in the test resouce
 * folder. Allow running of a single test from Unit testing GUIs
 */
public class PerlDKIMTest extends TestCase {

    private final File file;
    private MockPublicKeyRecordRetriever pkr;

    public PerlDKIMTest(String testName) throws IOException, URISyntaxException {
        this(testName, PerlDKIMTestSuite.getFile(testName),
                getPublicRecordRetriever());
    }

    public PerlDKIMTest(String name, File testFile,
                        MockPublicKeyRecordRetriever pkr) {
        super(name);
        this.file = testFile;
        this.pkr = pkr;
    }

    public static MockPublicKeyRecordRetriever getPublicRecordRetriever()
            throws IOException {
        MockPublicKeyRecordRetriever pkr = new MockPublicKeyRecordRetriever();
        BufferedReader fakeDNSlist = new BufferedReader(
                new InputStreamReader(
                        PerlDKIMTest.class.getResourceAsStream("/org/apache/james/jdkim/Mail-DKIM/FAKE_DNS.dat")));
        String line;
        while ((line = fakeDNSlist.readLine()) != null) {
            if (!line.startsWith("#")) {
                int pDK = line.indexOf("._domainkey.");
                int pSp = line.indexOf(" ");

                if (line.charAt(pSp + 1) == ' ') {
                    pkr.addRecord(line.substring(0, pDK), line.substring(pDK
                            + "._domainkey.".length(), pSp), line
                            .substring(pSp + 2));
                } else {
                    if (line.substring(pSp + 1).startsWith("~~")) {
                        pkr.addRecord(line.substring(0, pDK), line.substring(
                                pDK + "._domainkey.".length(), pSp), null);
                    } else {
                        // NXDOMAIN can be ignored
                    }
                }
            }
        }
        return pkr;
    }

    protected void runTest() throws Throwable {
        InputStream is = new FileInputStream(file);

        pkr = getPublicRecordRetriever();

        boolean expectFailure = false;
        boolean expectNull = false;
        // DomainKey files
        if (getName().contains("dk_"))
            expectNull = true;
            // older spec version
        else if (getName().contains("_ietf"))
            expectFailure = true;
        else if (getName().startsWith("multiple_1"))
            expectFailure = true;
        else if (getName().startsWith("no_body"))
            expectFailure = true;
            // invalid or inapplicable
        else if (getName().startsWith("badkey_"))
            expectFailure = true;
        else if (getName().startsWith("ignore_"))
            expectFailure = true;
        else if (getName().startsWith("bad_"))
            expectFailure = true;

        try {
            DKIMVerifier verifier = new DKIMVerifier(pkr);
            List<SignatureRecord> res = verifier.verify(is);

            if (getName().matches("good_dk_7|good_dk_6|dk_headers_2|good_dk_3")
                || getName().matches("|good_dk_gmail|dk_headers_1|good_dk_5|good_dk_4")
                    || getName().matches("good_dk_2|good_dk_yahoo|bad_dk_1|bad_dk_2|good_dk_1|dk_multiple_1")) {
                assertEquals(0, verifier.getResults().size());
            } else if (getName().equals("multiple_2")) {
                assertEquals(4, verifier.getResults().size());
                assertEquals(1, verifier.getResults().stream().filter(r -> r.getResultType() == Result.Type.PASS).count());
                assertEquals(1, verifier.getResults().stream().filter(r -> r.getResultType() == Result.Type.FAIL).count());
                assertEquals(2, verifier.getResults().stream().filter(r -> r.getResultType() == Result.Type.PERMERROR).count());
                assertEquals(1, verifier.getResults().stream().filter(r -> r.getResultType() == Result.Type.PASS
                        && r.getHeaderText().equals("dkim=pass header.d=messiah.edu header.s=selector1 header.b=keocS8z7y+ut")).count());
                assertEquals(1, verifier.getResults().stream().filter(r -> r.getResultType() == Result.Type.FAIL
                        && r.getHeaderText().equals("dkim=fail header.d=messiah.edu header.s=selector1 header.b=shouldfailut")).count());
            } else {
                assertEquals(1, verifier.getResults().size());
            }
            assertTrue(verifier.getResults().stream().allMatch(f  -> f.getRecord().getRawSignature() != null));
            if (expectNull)
                assertNull(res);
            if (expectFailure)
                fail("Failure expected!");
        } catch (FailException e) {
            if (!expectFailure)
                fail(e.getMessage());
        }
    }

    public static Test suite() throws IOException, URISyntaxException {
        return new PerlDKIMTestSuite();
    }

    static class PerlDKIMTestSuite extends TestSuite {

        private static final String TESTS_FOLDER = "/org/apache/james/jdkim/Mail-DKIM/corpus";

        public PerlDKIMTestSuite() throws IOException, URISyntaxException {
            URL resource = PerlDKIMTestSuite.class.getResource(TESTS_FOLDER);
            if (resource != null) {
                File dir = new File(resource.toURI());
                File[] files = dir.listFiles();

                if (files != null)
                    for (File f : files) {
                        if (f.getName().toLowerCase().endsWith(".txt")) {
                            addTest(new PerlDKIMTest(f.getName().substring(0,
                                    f.getName().length() - 4), f,
                                    getPublicRecordRetriever()));
                        }
                    }
            }
        }

        public static File getFile(String name) throws URISyntaxException {
            URL resource = PerlDKIMTestSuite.class.getResource(TESTS_FOLDER + File.separator + name + ".txt");
            if (resource != null) {
                return new File(resource.toURI());
            } else return null;
        }
    }
}