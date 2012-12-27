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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * This class handle a tag=value list string as defined by DKIM specification It
 * also supports mandatoryTags and default values as a commodity to subclasses.
 */
public class TagValue {

    private static final boolean DEBUG = false;
    protected static final boolean VALIDATION = true;

    private static final Pattern tagPattern = Pattern
            .compile("^[A-Za-z][A-Za-z0-9_]*$");
    // Use possessive matching to avoid heavy stack usage
    private static final String tval = "[^; \t\r\n]++";
    // validate value chars
    // Use possessive matching to avoid heavy stack usage
    private static final Pattern valuePattern = Pattern.compile("^(?:" + tval
            + "(?:(?:(?:\r\n)?[\t ])++" + tval + ")*+)?$");

    // we may use a TreeMap because we may need to know original order.
    private final Map<String, CharSequence> tagValues;

    protected final Set<String> mandatoryTags = new HashSet<String>();
    protected final Map<String, CharSequence> defaults = new HashMap<String, CharSequence>();
    private String stringRepresentation = null;

    protected Set<String> tagSet() {
        return tagValues.keySet();
    }
    protected boolean containsTag(String tag) {
        return tagValues.containsKey(tag);
    }
    
    protected CharSequence trimFWS(CharSequence data, int tStart, int tStop,
            boolean trimWSP) {
        if (DEBUG)
            System.out.println("1[" + data + "]" + tStart + "|" + tStop + "="
                    + data.subSequence(tStart, tStop + 1) + "]");
        // rimozione di FWS a inizio selezione
        while (tStart < tStop
                && (data.charAt(tStart) == ' ' || data.charAt(tStart) == '\t')
                || (tStart < tStop - 2 && data.charAt(tStart) == '\r'
                        && data.charAt(tStart + 1) == '\n' && (data
                        .charAt(tStart + 2) == ' ' || data.charAt(tStart + 2) == '\t'))) {
            if (data.charAt(tStart) == '\r')
                tStart += 3;
            else
                tStart++;
        }

        if (DEBUG)
            System.out.println("2[" + data + "]" + tStart + "|" + tStop + "="
                    + data.subSequence(tStart, tStop + 1) + "]");
        // rimozione di FWS a fine selezione.
        while (tStart < tStop
                && (data.charAt(tStop) == ' ' || data.charAt(tStop) == '\t')) {
            tStop--;
            if ((tStart <= tStop - 1 && data.charAt(tStop) == '\n' && data
                    .charAt(tStop - 1) == '\r')
                    || (tStart < tStop && (data.charAt(tStop) == ' ' || data
                            .charAt(tStop) == '\t'))) {
                if (data.charAt(tStop) == '\n')
                    tStop -= 2;
                else
                    tStop--;
            }
        }

        if (DEBUG)
            System.out.println("3[" + data + "]" + tStart + "|" + tStop + "="
                    + data.subSequence(tStart, tStop + 1) + "]");
        if (trimWSP) {
            return trimWSP(data, tStart, tStop);
        } else {
            return data.subSequence(tStart, tStop + 1);
        }
    }

    private CharSequence trimWSP(CharSequence data, int vStart, int vStop) {
        if (vStop < vStart - 1)
            throw new IllegalArgumentException("Stop must be >= than start");
        while (vStart <= vStop
                && (data.charAt(vStart) == ' ' || data.charAt(vStart) == '\t'))
            vStart++;
        while (vStart <= vStop
                && (data.charAt(vStop) == ' ' || data.charAt(vStop) == '\t'))
            vStop--;
        return data.subSequence(vStart, vStop + 1);
    }

    public TagValue(String data) {
        tagValues = newTagValue();
        init();
        parse(data);
    }

    protected Map<String, CharSequence> newTagValue() {
        // extensions may override this to use TreeMaps in order to keep track
        // of orders
        return new HashMap<String, CharSequence>();
    }

    protected void init() {
    }

    /**
     * subclasses have to make sure tagValues is initialized during init().
     * 
     * @param data
     *                the string to be parsed
     */
    protected void parse(String data) {
        for (int i = 0; i < data.length(); i++) {
            int equal = data.indexOf('=', i);
            if (equal == -1) {
                // TODO check whether this is correct or not
                // this allow FWS/WSP after the final ";"
                String rest = data.substring(i);
                if (rest.length() > 0
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
            if (tagValues.containsKey(tagString)) {
                throw new IllegalStateException(
                        "Syntax error (duplicate tag): " + tag);
            }

            CharSequence value = trimFWS(data, equal + 1, next - 1, true);
            if (VALIDATION && !valuePattern.matcher(value).matches()) {
                throw new IllegalStateException("Syntax error in value: "
                        + value);
            }

            tagValues.put(tagString, value);
            i = next;
        }
        this.stringRepresentation  = data;
    }

    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result
                + ((tagValues == null) ? 0 : tagValues.hashCode());
        return result;
    }

    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        TagValue other = (TagValue) obj;
        if (tagValues == null) {
            if (other.tagValues != null)
                return false;
        } else if (!tagValues.equals(other.tagValues))
            return false;
        return true;
    }

    public Set<String> getTags() {
        return tagValues.keySet();
    }

    protected CharSequence getValue(String key) {
        CharSequence val = tagValues.get(key);
        if (val == null)
            return getDefault(key);
        else
            return val;
    }
    
    protected void setValue(String tag, String value) {
        stringRepresentation = null;
        tagValues.put(tag, value);
    }


    protected CharSequence getDefault(String key) {
        return defaults.get(key);
    }

    public void validate() {
        // check mandatory fields
        for (String tag : mandatoryTags) {
            if (getValue(tag) == null)
                throw new IllegalStateException("Missing mandatory tag: " + tag);
        }
    }

    protected List<CharSequence> stringToColonSeparatedList(String h, Pattern pattern) {
        List<CharSequence> headers = new ArrayList<CharSequence>();
        for (int i = 0; i < h.length(); i++) {
            int p = h.indexOf(':', i);
            if (p == -1)
                p = h.length();
            CharSequence cs = trimFWS(h, i, p - 1, false);
            if (VALIDATION) {
                if (!pattern.matcher(cs).matches())
                    throw new IllegalStateException(
                            "Syntax error in field name: " + cs);
            }
            headers.add(cs);
            i = p;
        }
        return headers;
    }

    protected boolean isInListCaseInsensitive(CharSequence hash, List<CharSequence> hashes) {
        for (CharSequence suppHash : hashes) {
            if (hash.toString().equalsIgnoreCase(suppHash.toString()))
                return true;
        }
        return false;
    }

    public String toString() {
        if (stringRepresentation == null) {
            updateStringRepresentation();
        }
        return stringRepresentation;
    }
    
    private void updateStringRepresentation() {
        // calculate a new string representation
        StringBuilder res = new StringBuilder();
        Set<String> s = getTags();
        for (String tag : s) {
            res.append(" ");
            res.append(tag);
            res.append("=");
            res.append(getValue(tag));
            res.append(";");
        }
        // TODO add folding
        stringRepresentation = res.toString();
    }

}
