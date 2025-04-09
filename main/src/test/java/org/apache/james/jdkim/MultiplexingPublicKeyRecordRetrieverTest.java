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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;

import org.apache.james.jdkim.api.PublicKeyRecordRetriever;
import org.apache.james.jdkim.exceptions.FailException;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.exceptions.TempFailException;
import org.apache.james.jdkim.impl.MultiplexingPublicKeyRecordRetriever;
import org.assertj.core.util.Sets;
import org.junit.Test;

public class MultiplexingPublicKeyRecordRetrieverTest {

    private final PublicKeyRecordRetriever myMethodRetriever = (methodAndOption, selector, token) -> {
        List<String> l = new ArrayList<>();
        l.add(selector.toString());
        l.add(token.toString());
        return l;
    };


    @Test
    public void should_retrieve_records_by_known_method()
            throws TempFailException, PermFailException {
        MultiplexingPublicKeyRecordRetriever pkrr = new MultiplexingPublicKeyRecordRetriever(
                "mymethod",
                myMethodRetriever
        );

        check(pkrr, "mymethod");
    }

    @Test
    public void should_retrieve_records_by_known_method_with_options()
            throws TempFailException, PermFailException {
        MultiplexingPublicKeyRecordRetriever pkrr = new MultiplexingPublicKeyRecordRetriever(
                "mymethod",
                myMethodRetriever
        );

        check(pkrr, "mymethod/option");
    }


    @Test
    public void should_fail_on_unknown_method() throws TempFailException, PermFailException {
        MultiplexingPublicKeyRecordRetriever retriever = new MultiplexingPublicKeyRecordRetriever(
                "mymethod",
                myMethodRetriever
        );
        check(retriever, "mymethod");
        assertThatThrownBy(() ->
                retriever.getRecords("unknownMethod", "selector", "token")
        ).isInstanceOf(FailException.class);
    }

    @Test
    public void should_retrieve_records_from_several_known_methods() throws TempFailException, PermFailException {
        MultiplexingPublicKeyRecordRetriever retriever = new MultiplexingPublicKeyRecordRetriever(
                Sets.set(
                        MultiplexingPublicKeyRecordRetriever.Entry.of("myMethod", myMethodRetriever),
                        MultiplexingPublicKeyRecordRetriever.Entry.of("myOtherMethod", myMethodRetriever)
                )
        );
        check(retriever, "myMethod");
        check(retriever, "myOtherMethod");
        assertThatThrownBy(() ->
                retriever.getRecords("unknownMethod", "selector", "token")
        ).isInstanceOf(FailException.class);
    }

    @Test
    public void should_retrieve_records_from_several_known_methods_with_mixed_option() throws TempFailException, PermFailException {
        MultiplexingPublicKeyRecordRetriever retriever = new MultiplexingPublicKeyRecordRetriever(
                Sets.set(
                        MultiplexingPublicKeyRecordRetriever.Entry.of("myMethod", myMethodRetriever),
                        MultiplexingPublicKeyRecordRetriever.Entry.of("myOtherMethod", myMethodRetriever)
                )
        );
        check(retriever, "myMethod");
        check(retriever, "myMethod/option");
        check(retriever, "myOtherMethod");
        check(retriever, "myOtherMethod/option");
        assertThatThrownBy(() ->
                retriever.getRecords("unknownMethod", "selector", "token")
        ).isInstanceOf(FailException.class);
        assertThatThrownBy(() ->
                retriever.getRecords("unknownMethod/option", "selector", "token")
        ).isInstanceOf(FailException.class);
    }


    private void check(MultiplexingPublicKeyRecordRetriever pkrr, String method)
            throws TempFailException, PermFailException {
        List<String> records = pkrr.getRecords(method, "selector", "token");
        assertThat(records).containsExactly("selector", "token");
    }

}
