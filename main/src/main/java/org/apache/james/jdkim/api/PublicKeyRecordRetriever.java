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

import java.util.List;

import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.exceptions.TempFailException;

public interface PublicKeyRecordRetriever {

    /**
     * @param methodAndOption
     *                the options declared for the lookup method.
     * @param selector
     *                the value of "s=" tag
     * @param token
     *                the value of the "d=" tag
     * @return A list of strings representing 0 to multiple records
     * @throws TempFailException
     *                 in case of timeout and other network errors.
     * @throws PermFailException
     *                 in case of unsupported options
     */
    public List<String> getRecords(CharSequence methodAndOption,
            CharSequence selector, CharSequence token)
            throws TempFailException, PermFailException;

}
