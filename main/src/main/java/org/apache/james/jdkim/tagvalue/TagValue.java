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
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
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

    /**
     * System property disabling the strict syntax checks of tag values (RFC 6376 section 3.5 and 3.6.1)
     * when set to false: a verifier stricter than the others may reject real-world, slightly malformed records.
     * Checks with a semantic effect are never disabled. Defaults to true.
     */
    public static final String STRICT_VALIDATION_PROPERTY = "james.jdkim.strict.validation";

    /**
     * @return whether the strict syntax checks are enabled, see {@link #STRICT_VALIDATION_PROPERTY}
     */
    public static boolean isStrictValidation() {
        return !"false".equalsIgnoreCase(System.getProperty(STRICT_VALIDATION_PROPERTY, "true").trim());
    }

    // The syntax checks below are loops over the chars rather than regular expressions: they run for every
    // tag of every DKIM-Signature field and key record, and a loop does not recurse, which is why the former
    // patterns had to be possessive (a long z= overflowed the stack).
    private static final Pattern fwsPattern = Pattern.compile("[ \t\r\n]");

    // we may use a TreeMap because we may need to know original order.
    private final Map<String, CharSequence> tagValues;

    protected final Set<String> mandatoryTags = new HashSet<>();
    protected final Map<String, CharSequence> defaults = new HashMap<>();
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
            while ((tStart <= tStop - 1 && data.charAt(tStop) == '\n' && data
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
        return new HashMap<>();
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
                // only FWS may follow the final ";"
                if (!isFWS(data, i, data.length())) {
                    throw new IllegalStateException(
                            "Unexpected termination at position " + i + ": "
                                    + data + " | [" + data.substring(i) + "]");
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

            if (isStrictValidation()) {
                // SPEC: tag-spec = [FWS] tag-name [FWS] "=" [FWS] tag-value [FWS]: trimFWS removes any number of folds
                checkSingleFWSAround(data, i, equal);
                checkSingleFWSAround(data, equal + 1, next);
            }
            CharSequence tag = trimFWS(data, i, equal - 1, true).toString();
            if (VALIDATION && !isTagName(tag)) {
                throw new IllegalStateException("Syntax error in tag: " + tag);
            }
            String tagString = tag.toString();
            if (tagValues.containsKey(tagString)) {
                throw new IllegalStateException(
                        "Syntax error (duplicate tag): " + tag);
            }

            CharSequence value = trimFWS(data, equal + 1, next - 1, true);
            if (VALIDATION && !isValue(value)) {
                throw new IllegalStateException("Syntax error in value: "
                        + value);
            }

            tagValues.put(tagString, value);
            i = next;
        }
        this.stringRepresentation  = data;
    }

    /**
     * Checks that the whitespace that starts and ends data[start, end) is at most one FWS on each side:
     * FWS = [*WSP CRLF] 1*WSP holds a single CRLF, a line holding only WSP is obsolete syntax.
     * Whitespace alone may be two FWS, the one before and the one after an empty value.
     */
    private static void checkSingleFWSAround(String data, int start, int end) {
        int contentStart = start;
        while (contentStart < end && isFWSChar(data.charAt(contentStart))) {
            contentStart++;
        }
        int contentEnd = end;
        while (contentEnd > contentStart && isFWSChar(data.charAt(contentEnd - 1))) {
            contentEnd--;
        }
        if (contentStart == end) {
            // no content: the run holds the FWS before and the FWS after an empty value
            if (!isTwoFWS(data, start, end)) {
                throw new IllegalStateException("Syntax error: whitespace that is not FWS in ["
                        + data.substring(start, end) + "]");
            }
            return;
        }
        if (!isFWS(data, start, contentStart) || !isFWS(data, contentEnd, end)) {
            throw new IllegalStateException("Syntax error: whitespace that is not FWS in ["
                    + data.substring(start, end) + "]");
        }
    }

    private static boolean isFWSChar(char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    }

    private static boolean isWSP(char c) {
        return c == ' ' || c == '\t';
    }

    /**
     * @return the end of the FWS = [*WSP CRLF] 1*WSP that starts data[start, end) at start, or -1
     */
    private static int endOfFWS(CharSequence data, int start, int end) {
        int p = start;
        while (p < end && isWSP(data.charAt(p))) {
            p++;
        }
        if (p + 1 < end && data.charAt(p) == '\r' && data.charAt(p + 1) == '\n') {
            int q = p + 2;
            while (q < end && isWSP(data.charAt(q))) {
                q++;
            }
            return q > p + 2 ? q : -1;
        }
        return p > start ? p : -1;
    }

    /**
     * @return whether data[start, end) is empty or a single FWS
     */
    private static boolean isFWS(CharSequence data, int start, int end) {
        return start == end || endOfFWS(data, start, end) == end;
    }

    /**
     * @return whether data[start, end) is at most two FWS
     */
    private static boolean isTwoFWS(CharSequence data, int start, int end) {
        int p = start;
        for (int fws = 0; fws < 2 && p < end; fws++) {
            p = endOfFWS(data, p, end);
            if (p == -1) {
                return false;
            }
        }
        return p == end;
    }

    /**
     * SPEC: tag-name = ALPHA *ALNUMPUNC, ALNUMPUNC = ALPHA / DIGIT / "_"
     */
    private static boolean isTagName(CharSequence tag) {
        if (tag.length() == 0 || !isAlpha(tag.charAt(0))) {
            return false;
        }
        for (int i = 1; i < tag.length(); i++) {
            char c = tag.charAt(i);
            if (!isAlpha(c) && !(c >= '0' && c <= '9') && c != '_') {
                return false;
            }
        }
        return true;
    }

    private static boolean isAlpha(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    }

    /**
     * SPEC: tag-value = [ tval *( 1*(WSP / FWS) tval ) ], tval = 1*VALCHAR, VALCHAR = %x21-3A / %x3C-7E.
     * VALCHAR also takes the UTF8-non-ascii octets RFC 8616 section 4 allows in i= and z= for
     * internationalized mail: header octets are read as ISO-8859-1, so they arrive as U+0080 to U+00FF, and
     * the header hashing rejects anything above. Code points are checked, so a surrogate pair (above U+FFFF)
     * is not a VALCHAR.
     */
    private static boolean isValue(CharSequence value) {
        int n = value.length();
        int i = endOfTval(value, 0);
        if (n > 0 && i == 0) {
            return false;
        }
        while (i < n) {
            // 1*([CRLF] WSP) between two tval
            int j = i;
            while (true) {
                if (j < n && isWSP(value.charAt(j))) {
                    j++;
                } else if (j + 2 < n && value.charAt(j) == '\r' && value.charAt(j + 1) == '\n'
                        && isWSP(value.charAt(j + 2))) {
                    j += 3;
                } else {
                    break;
                }
            }
            int k = endOfTval(value, j);
            if (j == i || k == j) {
                return false;
            }
            i = k;
        }
        return true;
    }

    private static int endOfTval(CharSequence value, int start) {
        int i = start;
        while (i < value.length()) {
            int cp = Character.codePointAt(value, i);
            if (!((cp >= 0x21 && cp <= 0x3a) || (cp >= 0x3c && cp <= 0x7e) || (cp >= 0x80 && cp <= 0xffff))) {
                break;
            }
            i += Character.charCount(cp);
        }
        return i;
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
            return other.tagValues == null;
        } else return tagValues.equals(other.tagValues);
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

    protected byte[] decodeBase64TagValue(String key) {
        return decodeBase64(getValue(key));
    }

    /**
     * Decodes a base64string (RFC 6376 section 2.8): FWS may appear anywhere,
     * every other character must belong to the base64 alphabet.
     *
     * @throws IllegalArgumentException if the value is not valid base64
     */
    protected static byte[] decodeBase64(CharSequence value) {
        return Base64.getDecoder().decode(fwsPattern.matcher(value).replaceAll(""));
    }

    /**
     * Deletes the value of a tag, with the whitespace around it, and leaves the
     * rest of the tag-list as is (RFC 6376 section 3.7 for b=).
     */
    protected static String emptyTagValue(String tagList, String tag) {
        int start = 0;
        while (start <= tagList.length()) {
            int end = tagList.indexOf(';', start);
            if (end == -1)
                end = tagList.length();
            int equal = tagList.indexOf('=', start);
            if (equal != -1 && equal < end
                    && tag.equals(fwsPattern.matcher(tagList.subSequence(start, equal)).replaceAll(""))) {
                return tagList.substring(0, equal + 1) + tagList.substring(end);
            }
            start = end + 1;
        }
        return tagList;
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
        List<CharSequence> headers = new ArrayList<>();
        // SPEC: entry *( [FWS] ":" [FWS] entry ): neither an empty list nor a trailing ":"
        String trimmed = h.trim();
        if (isStrictValidation() && (trimmed.isEmpty() || trimmed.charAt(trimmed.length() - 1) == ':')) {
            throw new IllegalStateException("Syntax error in list: empty entry in [" + h + "]");
        }
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

    /**
     * Something parsed from a tag value, kept as long as the value (the same instance: values only change
     * through {@link #setValue(String, String)}) and the strictness of the validation are the same. The
     * parsed object must be immutable: it is returned to every caller.
     */
    protected static final class ParsedValue<T> {
        private final CharSequence source;
        private final boolean strict;
        private final T parsed;

        protected ParsedValue(CharSequence source, boolean strict, T parsed) {
            this.source = source;
            this.strict = strict;
            this.parsed = parsed;
        }

        protected boolean isFor(CharSequence source, boolean strict) {
            return this.source == source && this.strict == strict;
        }

        protected T get() {
            return parsed;
        }
    }

    /**
     * @return list, unmodifiable, or null
     */
    protected static List<CharSequence> unmodifiable(List<CharSequence> list) {
        return list == null ? null : Collections.unmodifiableList(list);
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
    
    /**
     * @return true to fold the generated string representation, see {@link #foldedRepresentation()}
     */
    protected boolean isFoldedRepresentation() {
        return false;
    }

    private void updateStringRepresentation() {
        if (isFoldedRepresentation()) {
            stringRepresentation = foldedRepresentation();
            return;
        }
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
        stringRepresentation = res.toString();
    }

    // RFC 5322 section 2.1.1: lines SHOULD be at most 78 characters, MUST be at most 998.
    private static final int FOLDING_WIDTH = 78;
    private static final int B64_CHUNK = 72;
    // the field name the representation is appended to, e.g. "DKIM-Signature:"
    private static final int FIELD_NAME_LENGTH = "DKIM-Signature:".length();

    /**
     * Folds the representation with CRLF + SP, as RFC 6376 section 3.5 allows. The b= value goes on
     * continuation lines of its own and the next tag on a new line, so that the folding of the other
     * tags does not depend on b=: removing the b= value (with its FWS) gives back the representation
     * generated with an empty b=, which is the one the signature is computed over.
     */
    private String foldedRepresentation() {
        StringBuilder res = new StringBuilder();
        int column = FIELD_NAME_LENGTH;
        boolean breakBeforeNextTag = false;
        for (String tag : getTags()) {
            String value = getValue(tag).toString();
            if ("b".equals(tag)) {
                String prefix = " b=";
                if (breakBeforeNextTag || column + prefix.length() + 1 > FOLDING_WIDTH) {
                    res.append("\r\n");
                    column = 0;
                }
                res.append(prefix);
                column += prefix.length();
                for (int i = 0; i < value.length(); i += B64_CHUNK) {
                    String chunk = value.substring(i, Math.min(value.length(), i + B64_CHUNK));
                    res.append("\r\n ").append(chunk);
                    column = 1 + chunk.length();
                }
                res.append(";");
                breakBeforeNextTag = true;
                continue;
            }
            String piece = " " + tag + "=" + value + ";";
            if (breakBeforeNextTag || (column > 0 && column + piece.length() > FOLDING_WIDTH)) {
                res.append("\r\n");
                column = 0;
            }
            breakBeforeNextTag = false;
            if (column + piece.length() <= FOLDING_WIDTH || !"h".equals(tag)) {
                res.append(piece);
                column = columnAfter(column, piece);
                continue;
            }
            // SPEC: sig-h-tag = hdr-name *( [FWS] ":" [FWS] hdr-name ): fold after a ":". The FWS the
            // value may already hold is dropped, so that a fold never lands next to an existing one.
            res.append(" h=");
            column += 3;
            String[] names = value.split(":", -1);
            for (int i = 0; i < names.length; i++) {
                String name = fwsPattern.matcher(names[i]).replaceAll("") + (i < names.length - 1 ? ":" : ";");
                if (column + name.length() > FOLDING_WIDTH) {
                    res.append("\r\n ");
                    column = 1;
                }
                res.append(name);
                column += name.length();
            }
        }
        return res.toString();
    }

    /**
     * @return the column after appending text at column: a CRLF the text holds starts a new line
     */
    private static int columnAfter(int column, String text) {
        int crlf = text.lastIndexOf("\r\n");
        if (crlf == -1) {
            return column + text.length();
        }
        return text.length() - crlf - 2;
    }

}
