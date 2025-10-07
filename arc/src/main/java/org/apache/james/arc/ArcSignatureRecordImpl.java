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
package org.apache.james.arc;

import org.apache.james.jdkim.tagvalue.SignatureRecordImpl;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
/**
 * Implementation of an ARC (Authenticated Received Chain) signature record.
 * <p>
 * This class extends {@link SignatureRecordImpl} to provide parsing, validation,
 * and string formatting for ARC signature header fields as defined in the ARC protocol.
 * It maintains the original order of tags and supports validation of expiration,
 * header lists, and tag/value syntax.
 * </p>
 */
public class ArcSignatureRecordImpl extends SignatureRecordImpl {
    private static final Pattern hdrNamePattern = Pattern.compile("^[^: \r\n\t]+$");
    private static final Pattern tagPattern = Pattern.compile("^[A-Za-z][A-Za-z0-9_]*$");
    private static final String tagValFormatPattern = "[^; \t\r\n]++";
    private static final Pattern valuePattern = Pattern.compile("^(?:" + tagValFormatPattern
            + "(?:(?:(?:\r\n)?[\t ])++" + tagValFormatPattern + ")*+)?$");
    private final Map<String, CharSequence> tagValuesOriginal = new LinkedHashMap<>();

    public ArcSignatureRecordImpl(String data) {
        super(data);
        parseOriginal(data);
    }

    @Override
    public void validate() throws IllegalStateException {
        if (getValue("x") != null) {
            long expiration = Long.parseLong(getValue("x").toString());
            long lifetime = (expiration - System.currentTimeMillis() / 1000);
            if (lifetime < 0) {
                throw new IllegalStateException("Signature is expired since "
                        + getTimeMeasureText(lifetime) + ".");
            }
        }
    }

    @Override
    public List<CharSequence> getHeaders() {
        if (getValue("h") == null)
            return new ArrayList<>();
        else
            return stringToColonSeparatedList(getValue("h").toString(),
                    hdrNamePattern);
    }

    private String getTimeMeasureText(long lifetime) {
        String measure = "s";
        lifetime = -lifetime;
        if (lifetime > 600) {
            lifetime = lifetime / 60;
            measure = "m";
            if (lifetime > 600) {
                lifetime = lifetime / 60;

                measure = "h";
                if (lifetime > 120) {
                    lifetime = lifetime / 24;
                    measure = "d";
                    if (lifetime > 90) {
                        lifetime = lifetime / 30;
                        measure = " months";
                        if (lifetime > 24) {
                            lifetime = lifetime / 12;
                            measure = " years";
                        }
                    }
                }
            }
        }
        return lifetime + measure;
    }

    @Override
    public String toUnsignedString() {
        String retValue = toString().replaceFirst("b=[^;]*", "b=");
        return getOrigOrderedString(retValue);
    }

    private String getOrigOrderedString(String retValue) {
        List<String> retValPartsList = Arrays.asList(retValue.trim().split(";"));
        StringBuilder sb = new StringBuilder();
        int originalTagIndex = 0;
        for (String tag : tagValuesOriginal.keySet()) {
            String tagPart = retValPartsList.stream().filter(p -> p.trim().startsWith(tag + "=")).findFirst().orElse(null);
            if (tagPart != null) {
                boolean isLastTag = originalTagIndex == tagValuesOriginal.size() - 1;
                if (tagPart.trim().startsWith("h") && tagPart.contains(":")) {
                    tagPart = tagPart.replace(":", " : ");
                    sb.append(tagPart.toLowerCase().trim());
                } else {
                    sb.append(tagPart.trim());
                }
                if (!isLastTag) {
                    sb.append("; ");
                }
            }
            originalTagIndex++;
        }
        return sb.toString();
    }

    public String getStringInTemplateOrder(){
        return getOrigOrderedString(toString());
    }

    private void parseOriginal(String data) {
        for (int i = 0; i < data.length(); i++) {
            int equal = data.indexOf('=', i);
            if (equal == -1) {
                String rest = data.substring(i);
                if (!rest.isEmpty()
                        && trimFWS(rest, 0, rest.length() - 1, true).length() > 0) {
                    throw new IllegalStateException(
                            "Unexpected termination at position " + i + ": "
                                    + data + " | [" + rest + "]");
                }
                i = data.length();
                continue;
            }
            // we could start from "equals" but we start from "i" in
            // order to spot invalid values before validation.
            int next = data.indexOf(';', i);
            if (next == -1) {
                next = data.length();
            }

            if (equal > next) {
                throw new IllegalStateException("Found ';' before '=' in "
                        + data);
            }

            CharSequence tag = trimFWS(data, i, equal - 1, true).toString();
            if (VALIDATION && !tagPattern.matcher(tag).matches()) {
                throw new IllegalStateException("Syntax error in tag: " + tag);
            }
            String tagString = tag.toString();
            if (tagValuesOriginal.containsKey(tagString)) {
                throw new IllegalStateException(
                        "Syntax error (duplicate tag): " + tag);
            }

            CharSequence value = trimFWS(data, equal + 1, next - 1, true);
            if (VALIDATION && !valuePattern.matcher(value).matches()) {
                throw new IllegalStateException("Syntax error in value: "
                        + value);
            }

            tagValuesOriginal.put(tagString, value);
            i = next;
        }
    }

    @Override
    public CharSequence getIdentity() {
        // In ARC, i= is just an integer
        return getValue("i");
    }

    @Override
    public CharSequence getIdentityLocalPart() {
        // Not applicable for ARC
        return getIdentity();
    }

    @Override
    public boolean equals(Object obj) {
        return super.equals(obj);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
