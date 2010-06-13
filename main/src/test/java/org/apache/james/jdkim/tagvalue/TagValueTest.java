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

package org.apache.james.jdkim.tagvalue;

import java.util.Set;

import junit.framework.TestCase;

public class TagValueTest extends TestCase {

    public void testEmpty() {
        new TagValue("");
    }

    public void testValid() {
        new TagValue("v=DKIM1; p=ciao; s=cips;");
        new TagValue("v=");
        new TagValue("v=;");
        assertTrue(tagValuesEquals("v=", "v=;"));
        assertTrue(tagValuesEquals("v=", "v= ;"));
        assertTrue(tagValuesEquals("v=", "v=\r\n ;"));
        assertFalse(tagValuesEquals("", "v=;"));
    }

    public void testInvalidSyntax() {
        try {
            new TagValue("_p=ciao; s=cips; v=DKIM1;");
            fail("expected invalid tag exception");
        } catch (IllegalStateException e) {
        }
    }

    public void testDoubleTag() {
        try {
            new TagValue("s=ciao; s=cips; v=DKIM1;");
            fail("expected duplicate tag exception");
        } catch (IllegalStateException e) {
        }
    }

    public void testInvalidFWS() {
        try {
            new TagValue("\r\n");
            fail("we only expect WSP/FWS withing a tag-value. No FWS/WSP allowed with no tag");
        } catch (IllegalStateException e) {
        }
    }

    public void testInvalidFWSSyntax() {
        try {
            new TagValue("p=test \r\n\r\n ");
            fail("expecting WSP after CRLF to handle it as FWS");
        } catch (IllegalStateException e) {
        }
        try {
            new TagValue("p=\r\n\r\n test");
            fail("expecting WSP after CRLF to handle it as FWS");
        } catch (IllegalStateException e) {
        }
    }

    public void testInvalidFWSStartSyntax() {
        try {
            new TagValue("\r\np=ciao; s=cips; v=DKIM1;");
            fail("\\r\\n at the beginning is not valid FWS");
        } catch (IllegalStateException e) {
        }
        try {
            new TagValue("\t\r\np=ciao; s=cips; v=DKIM1;");
            fail("\\t\\r\\n at the beginning is not valid FWS");
        } catch (IllegalStateException e) {
        }
    }

    public void testInvalidFWSEndSyntax() {
        try {
            new TagValue("p\r\n=ciao; s=cips; v=DKIM1;");
            fail("\\r\\n at the end is not valid FWS");
        } catch (IllegalStateException e) {
        }
        try {
            new TagValue("p \r\n=ciao; s=cips; v=DKIM1;");
            fail("\\r\\n at the end is not valid FWS");
        } catch (IllegalStateException e) {
        }
    }

    public void testValidFWSTags() {
        assertTrue(tagValuesEquals("\r\n\tp=ciao; s=cips; v=DKIM1;",
                "p=ciao;s=cips;v=DKIM1;"));
        assertTrue(tagValuesEquals("p\r\n =ciao; s=cips; v=DKIM1;",
                "p=ciao;s=cips;v=DKIM1;"));
        assertTrue(tagValuesEquals("p\r\n = \r\n\tciao; s=cips; v=DKIM1;",
                "p=ciao;s=cips;v=DKIM1;"));
        assertTrue(tagValuesEquals("p\r\n = ciao; s=cips\r\n\t; v=DKIM1;",
                "p=ciao;s=cips;v=DKIM1;"));
    }

    public void testNoTermination() {
        TagValue t = new TagValue("\r\n\tp=ciao; s=cips; v=DKIM1\r\n\t");
        assertEquals("DKIM1", t.getValue("v"));
    }

    // spaces around the value have to be stripped
    public void testSingleValue() {
        TagValue t = new TagValue("\r\n\tp  =      hi\t");
        assertEquals("hi", t.getValue("p"));
    }

    // spaces withing the value needs to be retained.
    public void testWSPinValue() {
        TagValue t = new TagValue("\r\n\tp  = \r\n hi \thi hi \t hi\t");
        assertEquals("hi \thi hi \t hi", t.getValue("p"));
    }

    // FWS withing the value needs to be retained.
    public void testFWSinValue() {
        TagValue t = new TagValue("\r\n\tp  = \r\n hi \thi\r\n hi \t hi\t");
        assertEquals("hi \thi\r\n hi \t hi", t.getValue("p"));
    }

    public void testNoEqual() {
        try {
            new TagValue("\r\n\tp        hi\t");
            fail("Expected value");
        } catch (IllegalStateException e) {
        }
        try {
            new TagValue("v=DKIM1; pciao; s=cips;");
            fail("Expected value");
        } catch (IllegalStateException e) {
        }
    }

    /**
     * TODO currently checking with the expert group to see if this is correct
     */
    public void testEndingWSP() {
        new TagValue("t=value; ");
    }

    public void testTagSetWithEquals() {
        TagValue tv = new TagValue("t=value; v=encoded=40value");
        Set<String> tags = tv.getTags();
        assertEquals(2, tags.size());
        assertTrue(tags.contains("t"));
        assertTrue(tags.contains("v"));
    }

    public boolean tagValuesEquals(String t1, String t2) {
        TagValue tv1 = new TagValue(t1);
        TagValue tv2 = new TagValue(t2);
        boolean eq = tv1.equals(tv2);
        if (eq)
            assertTrue(tv1.hashCode() == tv2.hashCode());
        return eq;
    }

}
