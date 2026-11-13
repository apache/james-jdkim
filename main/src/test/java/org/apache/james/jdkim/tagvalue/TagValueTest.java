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

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import org.junit.Assert;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

import java.util.Set;

public class TagValueTest {

    @Test
    public void testEmpty() {
        new TagValue("");
    }

    @Test
    public void testValid() {
        new TagValue("v=DKIM1; p=ciao; s=cips;");
        new TagValue("v=");
        new TagValue("v=;");
        Assert.assertTrue(tagValuesEquals("v=", "v=;"));
        Assert.assertTrue(tagValuesEquals("v=", "v= ;"));
        Assert.assertTrue(tagValuesEquals("v=", "v=\r\n ;"));
        Assert.assertFalse(tagValuesEquals("", "v=;"));
    }

    @Test
    public void testInvalidSyntax() {
        try {
            new TagValue("_p=ciao; s=cips; v=DKIM1;");
            Assert.fail("expected invalid tag exception");
        } catch (IllegalStateException e) {
        }
    }

    @Test
    public void testDoubleTag() {
        try {
            new TagValue("s=ciao; s=cips; v=DKIM1;");
            Assert.fail("expected duplicate tag exception");
        } catch (IllegalStateException e) {
        }
    }

    @Test
    public void testInvalidFWS() {
        try {
            new TagValue("\r\n");
            Assert.fail("we only expect WSP/FWS withing a tag-value. No FWS/WSP allowed with no tag");
        } catch (IllegalStateException e) {
        }
    }

    @Test
    public void testInvalidFWSSyntax() {
        try {
            new TagValue("p=test \r\n\r\n");
            Assert.fail("expecting WSP after CRLF to handle it as FWS");
        } catch (IllegalStateException e) {
        }
        try {
            new TagValue("p=\r\n\r\n test");
            Assert.fail("expecting WSP after CRLF to handle it as FWS");
        } catch (IllegalStateException e) {
        }
    }

    @Test
    public void testInvalidFWSStartSyntax() {
        try {
            new TagValue("\r\np=ciao; s=cips; v=DKIM1;");
            Assert.fail("\\r\\n at the beginning is not valid FWS");
        } catch (IllegalStateException e) {
        }
        try {
            new TagValue("\t\r\np=ciao; s=cips; v=DKIM1;");
            Assert.fail("\\t\\r\\n at the beginning is not valid FWS");
        } catch (IllegalStateException e) {
        }
    }

    @Test
    public void testInvalidFWSEndSyntax() {
        try {
            new TagValue("p\r\n=ciao; s=cips; v=DKIM1;");
            Assert.fail("\\r\\n at the end is not valid FWS");
        } catch (IllegalStateException e) {
        }
        try {
            new TagValue("p \r\n=ciao; s=cips; v=DKIM1;");
            Assert.fail("\\r\\n at the end is not valid FWS");
        } catch (IllegalStateException e) {
        }
    }

    @Test
    public void testValidFWSTags() {
        Assert.assertTrue(tagValuesEquals("\r\n\tp=ciao; s=cips; v=DKIM1;",
                "p=ciao;s=cips;v=DKIM1;"));
        Assert.assertTrue(tagValuesEquals("p\r\n =ciao; s=cips; v=DKIM1;",
                "p=ciao;s=cips;v=DKIM1;"));
        Assert.assertTrue(tagValuesEquals("p\r\n = \r\n\tciao; s=cips; v=DKIM1;",
                "p=ciao;s=cips;v=DKIM1;"));
        Assert.assertTrue(tagValuesEquals("p\r\n = ciao; s=cips\r\n\t; v=DKIM1;",
                "p=ciao;s=cips;v=DKIM1;"));
        Assert.assertTrue(tagValuesEquals("p=ciao\r\n  ; \r\n   s=cips\r\n\t; v=DKIM1;",
            "p=ciao;s=cips;v=DKIM1;"));
    }

    @Test
    public void testNoTermination() {
        TagValue t = new TagValue("\r\n\tp=ciao; s=cips; v=DKIM1\r\n\t");
        Assert.assertEquals("DKIM1", t.getValue("v"));
    }

    // spaces around the value have to be stripped
    @Test
    public void testSingleValue() {
        TagValue t = new TagValue("\r\n\tp  =      hi\t");
        Assert.assertEquals("hi", t.getValue("p"));
    }

    // spaces withing the value needs to be retained.
    @Test
    public void testWSPinValue() {
        TagValue t = new TagValue("\r\n\tp  = \r\n hi \thi hi \t hi\t");
        Assert.assertEquals("hi \thi hi \t hi", t.getValue("p"));
    }

    // FWS withing the value needs to be retained.
    @Test
    public void testFWSinValue() {
        TagValue t = new TagValue("\r\n\tp  = \r\n hi \thi\r\n hi \t hi\t");
        Assert.assertEquals("hi \thi\r\n hi \t hi", t.getValue("p"));
    }

    @Test
    public void testNoEqual() {
        try {
            new TagValue("\r\n\tp        hi\t");
            Assert.fail("Expected value");
        } catch (IllegalStateException e) {
        }
        try {
            new TagValue("v=DKIM1; pciao; s=cips;");
            Assert.fail("Expected value");
        } catch (IllegalStateException e) {
        }
    }

    /**
     * TODO currently checking with the expert group to see if this is correct
     */
    @Test
    public void testEndingWSP() {
        new TagValue("t=value; ");
    }

    @Test
    public void testTagSetWithEquals() {
        TagValue tv = new TagValue("t=value; v=encoded=40value");
        Set<String> tags = tv.getTags();
        Assert.assertEquals(2, tags.size());
        Assert.assertTrue(tags.contains("t"));
        Assert.assertTrue(tags.contains("v"));
    }

    public boolean tagValuesEquals(String t1, String t2) {
        TagValue tv1 = new TagValue(t1);
        TagValue tv2 = new TagValue(t2);
        boolean eq = tv1.equals(tv2);
        if (eq)
            assertTrue(tv1.hashCode() == tv2.hashCode());
        return eq;
    }

    @Test
    public void valuesOutsideValcharShouldBeRejected() {
        assertThatThrownBy(() -> new TagValue("a=\u000b")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new TagValue("a=\u007f")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new TagValue("a=b\u0000c")).isInstanceOf(IllegalStateException.class);
    }

    @Test
    public void utf8OctetsShouldBeAccepted() {
        assertEquals("j\u00c3\u00a9r\u00c3\u00b4me", new TagValue("a=j\u00c3\u00a9r\u00c3\u00b4me").getValue("a").toString());
    }

    @Test
    public void trailingWhitespaceThatIsNotFwsShouldBeRejected() {
        assertThatThrownBy(() -> new TagValue("a=b;\r\n\r\n\t")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new TagValue("\r\n\r\n\r\n\t")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new TagValue("a=b;\r\n")).isInstanceOf(IllegalStateException.class);
    }

    @Test
    public void trailingFwsShouldBeAccepted() {
        new TagValue("a=b; ");
        new TagValue("a=b; \r\n\t");
        new TagValue("a=b;\r\n ");
    }

    @Test
    public void blankLineInsideATagSpecShouldBeRejected() {
        assertThatThrownBy(() -> new TagValue("v=1\r\n\r\n ")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new TagValue("a\r\n\r\n =b")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new TagValue("v=\r\n\r\n ;f=1")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new TagValue("p=ciao\r\n\r\n  ; s=cips")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new TagValue(" \r\n \r\n a=b")).isInstanceOf(IllegalStateException.class);
    }

    @Test
    public void singleFoldAroundATagSpecShouldBeAccepted() {
        assertEquals("1", new TagValue("v=1\r\n ").getValue("v").toString());
        assertEquals("b", new TagValue("a\r\n =b;\r\n\tc=d").getValue("a").toString());
        assertEquals("", new TagValue("v= \r\n\t;f=1").getValue("v").toString());
    }

    @Test
    public void twoFoldsAroundAnEmptyValueShouldBeAccepted() {
        // [FWS] tag-value [FWS] with an empty tag-value: two FWS, one fold each
        assertEquals("", new TagValue("b\r\n\t=\r\n\t\r\n\t").getValue("b").toString());
        assertEquals("", new TagValue("v=\r\n \r\n ;f=1").getValue("v").toString());
        assertEquals("", new TagValue("v= \t\r\n \t\r\n\t ;f=1").getValue("v").toString());
    }

    @Test
    public void moreThanTwoFoldsAroundAnEmptyValueShouldBeRejected() {
        assertThatThrownBy(() -> new TagValue("v=\r\n \r\n \r\n ;f=1")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new TagValue("v=\r\n\r\n ;f=1")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new TagValue("v= \r\n")).isInstanceOf(IllegalStateException.class);
    }
}
