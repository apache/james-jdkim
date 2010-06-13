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

public interface Headers {

    /**
     * Gets the fields of this header. The returned list will not be modifiable.
     * 
     * @return the list of <code>Field</code> objects.
     */
    public abstract List<String> getFields();

    /**
     * Gets all <code>Field</code>s having the specified field name in a case
     * insensitive way.
     * 
     * @param name
     *                the field name (e.g. From, Subject).
     * @return the list of fields.
     */
    public abstract List<String> getFields(final String name);

}