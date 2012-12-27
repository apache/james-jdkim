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

import org.apache.james.jdkim.api.PublicKeyRecordRetriever;
import org.apache.james.jdkim.exceptions.FailException;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.exceptions.TempFailException;
import org.apache.james.jdkim.impl.MultiplexingPublicKeyRecordRetriever;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class MultiplexingPublicKeyRecordRetrieverTest {

    private final PublicKeyRecordRetriever myMethodRetriever = new PublicKeyRecordRetriever() {

        public List<String> getRecords(CharSequence methodAndOption,
                                       CharSequence selector, CharSequence token)
                throws TempFailException, PermFailException {
            List<String> l = new ArrayList<String>();
            l.add(selector.toString());
            l.add(token.toString());
            return l;
        }

    };

    @Test
    public void testMultiplexingPublicKeyRecordRetriever() {
        MultiplexingPublicKeyRecordRetriever pkrr = new MultiplexingPublicKeyRecordRetriever();
        try {
            pkrr.getRecords("method", "selector", "token");
            fail("method is unknown");
        } catch (FailException e) {
        }
    }

    @Test
    public void testMultiplexingPublicKeyRecordRetrieverStringPublicKeyRecordRetriever()
            throws TempFailException, PermFailException {
        MultiplexingPublicKeyRecordRetriever pkrr = new MultiplexingPublicKeyRecordRetriever(
                "mymethod", myMethodRetriever);
        check(pkrr, "mymethod");
    }

    private void check(MultiplexingPublicKeyRecordRetriever pkrr, String method)
            throws TempFailException, PermFailException {
        List<String> l = pkrr.getRecords(method, "selector", "token");
        Iterator<String> i = l.iterator();
        assertEquals("selector", i.next());
        assertEquals("token", i.next());
        try {
            l = pkrr.getRecords("anothermethod", "selector", "token");
            fail("anothermethod is not declared");
        } catch (FailException e) {
        }
    }

    @Test
    public void testAddRetriever() throws TempFailException, PermFailException {
        MultiplexingPublicKeyRecordRetriever pkrr = new MultiplexingPublicKeyRecordRetriever();
        pkrr.addRetriever("mymethod", myMethodRetriever);
        check(pkrr, "mymethod");
    }

    @Test
    public void testAddRetrieverWithOptions() throws TempFailException,
            PermFailException {
        MultiplexingPublicKeyRecordRetriever pkrr = new MultiplexingPublicKeyRecordRetriever();
        pkrr.addRetriever("mymethod", myMethodRetriever);
        check(pkrr, "mymethod/option");
    }

}
