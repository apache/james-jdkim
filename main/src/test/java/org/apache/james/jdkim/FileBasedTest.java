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
import org.apache.james.jdkim.exceptions.PermFailException;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Creates a TestSuite running the test for each .msg file in the test resouce
 * folder. Allow running of a single test from Unit testing GUIs
 */
public class FileBasedTest extends TestCase {

    private File file;

    public FileBasedTest(String testName) throws URISyntaxException {
        this(testName, FileBasedTestSuite.getFile(testName));
    }

    public FileBasedTest(String name, File testFile) {
        super(name);
        this.file = testFile;
    }

    protected void runTest() throws Throwable {
        InputStream is = new FileInputStream(file);
        // String msgoutFile = file.getAbsolutePath().substring(0,
        // file.getAbsolutePath().lastIndexOf('.')) + ".out";

        MockPublicKeyRecordRetriever pkr = new MockPublicKeyRecordRetriever();
        pkr
                .addRecord(
                        "domk",
                        "brainlounge.de",
                        "t=y; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMxdtsTy8K7yEHt+7DB4XH70Rd6v7rp2qai7gM1meDzlrwDlMzUi0mQC+dMY+AzmCE1jLNXAr3JL6kT8vD7KQai8avwGQzmlU3d0Z7etqTj1ttJQZxUTPM18bM3wVqc6h3Dppqx7kY91Td50r9MXBbu+DkhL1+RCfcPQxEvEf74QIDAQAB");
        pkr
                .addRecord(
                        "dkim",
                        "paypal.it",
                        "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD3j+gKW1qBM+psRHXAdR7tI9QcKW0Ii723AzyTO4nrVmuJoKWHLoEEQw/Nc4XF7iyhfadorjqZZ9f+qDXQiKPyLJyVXs0qLrnJQ9BWlQP0xIiz7CTcoHwEhJ1XwgUI/2V6bNghMrnK2yiR/Vqt5lV5kx4+n1656EefGuOTuNmIWwIDAQAB");
        pkr
                .addRecord(
                        "default",
                        "gfkresearch.com",
                        "t=y; p=MHwwDQYJKoZIhvcNAQEBBQADawAwaAJhAM26TUEN/IatWRhSiguj8RyDmeFRQJG8gaNjdaOOJ3AZuGeCG1W9NwlkgDv7UxUUx3AIkFbU/wsDFMe/RGItcK5vKEkUP0roJ1fCTtYsfTHhmnhXyJsmj0eDvbwDg6BzfwIDAQAB");
        pkr
                .addRecord(
                        "2007-00",
                        "kitterman.com",
                        "v=DKIM1; g=*; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCp9+s7hHTlMje842UBfd8nBYvX0I1CJzltQJ9bLGAKHbyCBTKei/dYuuDICKArbcVZ+05UbJzxU6cstPOaEoPM+FMD/lUiGpJYLYUuzRP7Pd82YHKoAZbYflGYTck2e7x8vB7l8WeEgRJ0cJdHm871HbQmv67LZiN+9donmjl93wIDAQAB;");
        pkr
                .addRecord(
                        "beta",
                        "gmail.com",
                        "t=y; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC69TURXN3oNfz+G/m3g5rt4P6nsKmVgU1D6cw2X6BnxKJNlQKm10f8tMx6P6bN7juTR1BeD8ubaGqtzm2rWK4LiMJqhoQcwQziGbK1zp/MkdXZEWMCflLY6oUITrivK7JNOLXtZbdxJG2y/RAHGswKKyVhSP9niRsZF/IBr5p8uQIDAQAB");
        pkr
                .addRecord(
                        "gamma",
                        "gmail.com",
                        "k=rsa; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIhyR3oItOy22ZOaBrIVe9m/iME3RqOJeasANSpg2YTHTYV+Xtp4xwf5gTjCmHQEMOs0qYu0FYiNQPQogJ2t0Mfx9zNu06rfRBDjiIU9tpx2T+NGlWZ8qhbiLo5By8apJavLyqTLavyPSrvsx0B3YzC63T4Age2CDqZYA+OwSMWQIDAQAB");
        pkr
                .addRecord(
                        "beta",
                        "google.com",
                        "k=rsa; t=y; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMs93oc95ObA7OEQEbqjIy6YvRj1u3yVGTzQ3wkwRQTWx1fhvNQenPNFklaL+Tw9XFYUc3f8eY0hs3WUNQ+t+I0CAwEAAQ==");
        pkr
                .addRecord(
                        "beta",
                        "googlegroups.com",
                        "t=y; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDs66DgKyXSlBvNCbi158TgsBzqh/n7GqCa2QwIORpNbndjlK8qaR9mb8gH9KG1S3ahZybrZT1N268dgF2VDWV14h1fpPMIj6KKoX6uzGomzIVdeGPmjZ7o3ZUaxHUWvwIEGlNv400xzBToSU44sXqQIwH5l08anWYw3sq9xBrI5wIDAQAB");
        pkr
                .addRecord(
                        "gamma",
                        "googlemail.com",
                        "k=rsa; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIhyR3oItOy22ZOaBrIVe9m/iME3RqOJeasANSpg2YTHTYV+Xtp4xwf5gTjCmHQEMOs0qYu0FYiNQPQogJ2t0Mfx9zNu06rfRBDjiIU9tpx2T+NGlWZ8qhbiLo5By8apJavLyqTLavyPSrvsx0B3YzC63T4Age2CDqZYA+OwSMWQIDAQAB");
        pkr
                .addRecord(
                        "s768",
                        "t.contactlab.it",
                        "k=rsa; p=MHwwDQYJKoZIhvcNAQEBBQADawAwaAJhAMUUS6qlVpzbGQ3SCsGwpuVlC6gtw+BXMkFhm+jd57GXPtwpbOgr+UaHlbq6OnFAgrHxVx55RrSsTxixw0t0ePGkdBHjE7fURGphf+Mr1gzhvvLO6j1f1/60zvQPyay5UQIDAQAB");
        pkr
                .addRecord(
                        "s768",
                        "contactlab.it",
                        "k=rsa; p=MHwwDQYJKoZIhvcNAQEBBQADawAwaAJhAMUUS6qlVpzbGQ3SCsGwpuVlC6gtw+BXMkFhm+jd57GXPtwpbOgr+UaHlbq6OnFAgrHxVx55RrSsTxixw0t0ePGkdBHjE7fURGphf+Mr1gzhvvLO6j1f1/60zvQPyay5UQIDAQAB");
        pkr
                .addRecord(
                        "emailroi",
                        "mediapost.com",
                        "g=; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC61RrUNTIcNbf/+f5Co2V37GMvPQdbUVyjgvLXrUKAXeJDwYVumAtE9BovuDZNYxcgG2oy7mkcZX/3rBF2SJX9Cp5yw0axuMpzkuzPQq26h+2+MLuvtJtfDIaHgNeEJOjMeq7s9RFQHRr9g26lkZQTRAob8YevaA9KHiNNyIaZuQIDAQAB;");
        pkr
                .addRecord(
                        "dkim_s1024",
                        "aweber.com",
                        "v=DKIM1; k=rsa; h=sha1; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRAeDcyfWZQQ9sv+qRMQVTda/9yyYMo9qdI+h3i4U68+rrEruEoxLaa0JJw6OwFXzQ9x9raHZjroHsySzzQbIiZLj9o4IoCqpt5v0xd45+ABhQM6DyzHZDgIFcMtYIzEjaKLzkVpNeS9qr8Cra7CLtSqCbdAjGyUgVLveHrxNP9wIDAQAB");
        pkr
                .addRecord(
                        "itunes",
                        "new-music.itunes.com",
                        "v=DKIM1; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMTdhQ9CBNvwYGPkggikcMqT90O4JAzPfxtPaeJ1CgfTlXk0GL3OTz1nfeN3w2ybTpIKYRLrW23Qppaunpb/3dMCAwEAAQ==;");
        pkr
                .addRecord(
                        "lima",
                        "yahoogroups.com",
                        "k=rsa; p=MHwwDQYJKoZIhvcNAQEBBQADawAwaAJhAL10WHRWMSb9Tnl+k4Kzpc18rDCTpDT1pbK0xwkdZIZkaP8NB75qa/S57xccZlIwbI22Ooy/IY+8WxQtvE2z4WLLNOf9hkMeicUH48TGkEoCAcaSjJz/b3NMrOy9l1U7gQIDAP//");
        pkr
                .addRecord(
                        "s1024",
                        "yahoo.co.in",
                        "k=rsa; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDrEee0Ri4Juz+QfiWYui/E9UGSXau/2P8LjnTD8V4Unn+2FAZVGE3kL23bzeoULYv4PeleB3gfmJiDJOKU3Ns5L4KJAUUHjFwDebt0NP+sBK0VKeTATL2Yr/S3bT/xhy+1xtj4RkdV7fVxTn56Lb4udUnwuxK4V5b5PdOKj/+XcwIDAQAB; n=A 1024 bit key;");
        pkr
                .addRecord(
                        "k1",
                        "adidasnewsletter.com",
                        "t=y; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3VqSTEgEkHtfDiMCzoYtY1wjcArcmb+efQJfzX4zJA60IEA/NmOaHP8Gu02vscLbJWT/mwGlZwr2Q53g9VMQOyoODD5ju1EwJwlioVQ1W7xSjogMTz8yzmWhcMUzXQOu/iD+7sdJP0+k7pCumPMbxEeN33At7HxoYVCSkNdUB9QIDAQAB");
        pkr
                .addRecord(
                        "200505",
                        "yahoo-email.com",
                        "t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDaMFcW5fNoye1Xo7BT/lKCHThjn1QaVdcxoAy7Y1m2tXnR3X+qUxFRaoyReTVlxfO8vaIPSbJ2Pm6+sZkC0lH/6Ok+i0RDhtd7bq9oLFKclfMGQlphBB185c1zDKNTs7GyAyjSM7pEzx5Dai+YTE9/+GYhdbEWmGBS9TsXnTCKPQIDAQAB");
        pkr
                .addRecord(
                        "v1",
                        "alerts.hp.com",
                        "k=rsa; p=MHwwDQYJKoZIhvcNAQEBBQADawAwaAJhAPSCrSVhxHa6F3EpDjnw6xdpfTv8sNz5Plbl3b3Zqq9WVVg2j5+748EkwtvzQlA6TQuZIOrpSHJkP0nEyCR5GatNasOKPWFO47VSLFO9AJbsc34eGUUTF49bBIACiE4b9wIDAQAB");
        pkr
                .addRecord(
                        "v1",
                        "rodale.delivery.net",
                        "k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCWWvSsm60Wx178Y7pET3m/UZaof+qtRxZa8RXfyTIiGYMXJFwHgd3VrTLF6xmoCyRC1kfv3k7nPujkGFydBCoRK/vCN/1e4yHAsSwh/ElTO5dqylvP77PJyiaME582m4wXf095NBXJZlHUlXb7SWDdmCeU5uXfcR0EJU0eRewflQIDAQAB");
        pkr
                .addRecord(
                        "domk",
                        "brainlounge.de",
                        "t=y; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMxdtsTy8K7yEHt+7DB4XH70Rd6v7rp2qai7gM1meDzlrwDlMzUi0mQC+dMY+AzmCE1jLNXAr3JL6kT8vD7KQai8avwGQzmlU3d0Z7etqTj1ttJQZxUTPM18bM3wVqc6h3Dppqx7kY91Td50r9MXBbu+DkhL1+RCfcPQxEvEf74QIDAQAB");
        pkr
                .addRecord(
                        "spop",
                        "newsletters.play.com",
                        "g=; k=rsa; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOaOtP9KfyxvWET0yXoL2ugcas2SjoBZ+40oZ6/twAEtW224fcuvOFiNS+XpPq5LNW96NYAuxJPBlwLoYlHRUQkCAwEAAQ==");
        pkr
                .addRecord(
                        "ironport-dkim",
                        "ironport.com",
                        "p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJqzyi+tkPHw4hrcTSJBXTh3m2koCKP0+J6/r+yVVg7VoRKPz/tguE+M6fF0oqLk5Fci+tE8HFS3HLkl0au17CcCAwEAAQ==;");
        pkr
                .addRecord(
                        "smtp-out",
                        "abv.bg",
                        "g=*; k=rsa; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDPShtI1XjhVGpVrKyBuFP5K0jqFqy5gC8GujqF9lTCN/Epg/kObBOORSVAZ0DRawBHyRWDcscPwK8MhzQb2ZjRKGGK1L6OqaDQL5y9o0f2dqtuwMzGqJyaIL4Wrs3v0YbqD1w4G6pq/5NxfPpKyKqAbiCTGrutCo/dQaRF/YjPnQIDAQAB");
        pkr
                .addRecord(
                        "rte02",
                        "amazon.co.uk",
                        "p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJ8ZPV/qBm64HtL09YSynw1kPGlSPb0ZGiqcKuXfMh36SZhzj0ejzl4gktXsaA7P1G59gsxtl47q58aFkDV/sfMCAwEAAQ==;");
        pkr
                .addRecord(
                        "bnpparibas.com",
                        "bnpparibas.com",
                        "t=y; k=rsa; p=MHwwDQYJKoZIhvcNAQEBBQADawAwaAJhANNNDEMXsk1tiHUpJyNQjjRvO2FtxvD0+JcRiugSUpHysjlKpU8mghN7U12veeN8msqyIen4XExVIIQiJ8xNM3RSaqijRdfvP/8BKHB8jvMyeK6WXJa/epUXvEbc1LDbqQIDAQAB;");
        pkr
                .addRecord(
                        "dkim",
                        "paypal.it",
                        "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD3j+gKW1qBM+psRHXAdR7tI9QcKW0Ii723AzyTO4nrVmuJoKWHLoEEQw/Nc4XF7iyhfadorjqZZ9f+qDXQiKPyLJyVXs0qLrnJQ9BWlQP0xIiz7CTcoHwEhJ1XwgUI/2V6bNghMrnK2yiR/Vqt5lV5kx4+n1656EefGuOTuNmIWwIDAQAB");
        pkr
                .addRecord(
                        "emarsys2007",
                        "reply.ebay.it",
                        "t=y; k=rsa; p=MHwwDQYJKoZIhvcNAQEBBQADawAwaAJhAN0+C5B9PA1ZtdxRvF5hmETzHwQ2NvEmpHILm4afsY16Gw2JVEmwGuXUmyAmbAdQjERKbll1mFQ+9oPcmpr4uwcPHRfE6b2s8V4YK7vofxKJjZ+3PK6jtP4FMHXso/C1+wIDAQAB;");
        pkr
                .addRecord(
                        "q1-2009b",
                        "facebookmail.com",
                        "k=rsa; t=s; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKrBYvYESXSgiYzKNufh9WG8cktn2yrmdqGs9uz8VL6Mz44GuX8xJAQjpmPObe6p2vfTMWeztKEudwY6ei7UcZMCAwEAAQ==");
        pkr
                .addRecord(
                        "spop",
                        "em.fileplanet.com",
                        "g=; k=rsa; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALsyVo5aJtEzBm5p3+7N/7d0HfczMgJnsqapraAgMe+K2ng9gWsXvAugwh1/OlhzkA69ZCFck47qSN/wGFDwEFUCAwEAAQ==");
        pkr
                .addRecord(
                        "default",
                        "bouncemanager.it",
                        "v=DKIM1; g=*; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUekin7hdVzGRw3k0iKRyg0MSj1PeC94A7wzOT0L9cQW0fIEeIM07bmAwbc4MgXnScPGiZnhPDVNxO40YUNbR9JOc+EoESSErWUCHeNYm7dyPG1aVEvfUT+OKprEwFldAdSv9c/C92otFdlWd8lSTuYiE1qNHhQim+7kzdV7SEUQIDAQAB");
        pkr
                .addRecord(
                        "default",
                        "gfkresearch.com",
                        "t=y; p=MHwwDQYJKoZIhvcNAQEBBQADawAwaAJhAM26TUEN/IatWRhSiguj8RyDmeFRQJG8gaNjdaOOJ3AZuGeCG1W9NwlkgDv7UxUUx3AIkFbU/wsDFMe/RGItcK5vKEkUP0roJ1fCTtYsfTHhmnhXyJsmj0eDvbwDg6BzfwIDAQAB");
        pkr
                .addRecord(
                        "key1",
                        "listrak.com",
                        "k=rsa; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAPM8yO1kwQBzUUq6PP0epEshX1Vm7ThUrCddHgCn3b0llq8NRvGw5eOQBKySYngTkYyd5M0fImghDxxDsAnC9DsCAwEAAQ==");
        pkr
                .addRecord(
                        "mail",
                        "emailsadvertiser.com",
                        "k=rsa; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDrf8/zzjRv85obYOx6GQjjNba/ m9uNLWKA53vHJNm/y69jM8+3rJr5eAAEJWpt7czNVkrWzwztfYRvai5Bs2Yvv5hS WbKl6Zr93s7I1HBn7MjCFZFW/MWeqlIydj+D8Zyy6ASqb9dYjD8qcLnncUse72du 6fEdEo/CR++P9x6sxwIDAQAB");
        pkr
                .addRecord(
                        "proddkim",
                        "linkedin.com",
                        "v=DKIM1; t=y:s; p=MHwwDQYJKoZIhvcNAQEBBQADawAwaAJhAM+u1MLWZz+wOnU/C53PqLT4ITdkq+TC1xkWcoRMXq2FVH1kvXRxtqfbL4k5vYh7JVQ6nPrS+ldEpIbJzVaxhP5Kggi4SNfdf8GdbpGXcJj6SHKRFb8Mryp0ilk2XecLcQIDAQAB;");
        pkr
                .addRecord(
                        "s1024",
                        "yahoo.com",
                        "k=rsa; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDrEee0Ri4Juz+QfiWYui/E9UGSXau/2P8LjnTD8V4Unn+2FAZVGE3kL23bzeoULYv4PeleB3gfmJiDJOKU3Ns5L4KJAUUHjFwDebt0NP+sBK0VKeTATL2Yr/S3bT/xhy+1xtj4RkdV7fVxTn56Lb4udUnwuxK4V5b5PdOKj/+XcwIDAQAB; n=A 1024 bit key;");
        pkr
                .addRecord(
                        "pmta",
                        "myspace.com",
                        "k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQChRebhcm4h8BkIYHRxg1GlKLsDkwdrqkFJ8f88xHQ5Gf3NH4I4e06M3XQ+B4tWWK/rX0srwXFgrJPzKZK+x7gN89nmqyM+NNaM+Wm2C0GjTpx6639zK3bAAGYCm0L9lGD7PgDxpWok+YogH0Ml4acEwDw/cnhErAWAnX8doPliawIDAQAB");

        try {
            List<SignatureRecord> res = new DKIMVerifier(pkr).verify(is);
            if (getName().startsWith("NONE_"))
                assertNull(res);
            if (getName().startsWith("FAIL_"))
                fail("Expected failure");
        } catch (PermFailException e) {
            if (!getName().startsWith("FAIL_"))
                fail(e.getMessage());
        }
    }

    public static Test suite() throws IOException, URISyntaxException {
        return new FileBasedTestSuite();
    }

    static class FileBasedTestSuite extends TestSuite {

        private static final String TESTS_FOLDER = "/org/apache/james/jdkim/corpus";

        public FileBasedTestSuite() throws IOException, URISyntaxException {
            URL resource = FileBasedTestSuite.class.getResource(TESTS_FOLDER);
            if (resource != null) {
                File dir = new File(resource.toURI());
                File[] files = dir.listFiles();

                if (files != null)
                    for (int i = 0; i < files.length; i++) {
                        File f = files[i];
                        if (f.getName().toLowerCase().endsWith(".eml")) {
                            addTest(new FileBasedTest(f.getName().substring(0,
                                    f.getName().length() - 4), f));
                        }
                    }
            }
        }

        public static File getFile(String name) throws URISyntaxException {
            URL resource =  FileBasedTestSuite.class.getResource(TESTS_FOLDER + File.separator + name + ".eml");
            if (resource != null) {
                return new File(resource.toURI());
            } else return null;
        }

    }
}