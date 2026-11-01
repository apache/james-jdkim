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

import org.apache.james.jdkim.api.PublicKeyRecord;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class PublicKeyRecordImpl extends TagValue implements PublicKeyRecord {

    private static final String atom = "[a-zA-Z0-9!#$%&'*+/=?^_`{}|~-]+";
    // TODO this should support CFWS: are they supported in DKIM for real?
    private static final String dotAtomText = "(" + atom + ")?\\*?(" + atom
            + ")?";
    private static final Pattern granularityPattern = Pattern.compile("^"
            + dotAtomText + "$");

    // SPEC: hyphenated-word = ALPHA [ *(ALPHA / DIGIT / "-") (ALPHA / DIGIT) ]
    private static final Pattern hyphenatedWordPattern = Pattern
            .compile("^[a-zA-Z]([a-zA-Z0-9-]*[a-zA-Z0-9])?$");

    // SPEC: key-s-tag-type = "email" / "*" / x-key-s-tag-type ; x-key-s-tag-type = hyphenated-word
    private static final Pattern serviceTypePattern = Pattern
            .compile("^(\\*|[a-zA-Z]([a-zA-Z0-9-]*[a-zA-Z0-9])?)$");

    public PublicKeyRecordImpl(String data) {
        super(data);
    }

    protected Map<String, CharSequence> newTagValue() {
        // extensions may override this to use TreeMaps in order to keep track
        // of orders
        return new LinkedHashMap<String, CharSequence>();
    }

    protected void init() {
        mandatoryTags.add("p");
        defaults.put("v", "DKIM1");
        defaults.put("g", "*");
        defaults.put("h", ANY);
        defaults.put("k", "rsa");
        defaults.put("s", "*");
        defaults.put("t", "");
    }

    // TODO do we treat v=NONDKIM1 records, syntax error records and v=DKIM1 in
    // the middle records in the same way?
    public void validate() {
        super.validate();
        if (containsTag("v")) {
            // if "v" is specified it must be the first tag
            String firstKey = tagSet().iterator().next();
            if (!"v".equals(firstKey))
                throw new IllegalStateException(
                        "Existing v= tag MUST be the first in the record list ("
                                + firstKey + ")");
        }
        if (!"DKIM1".equals(getValue("v")))
            throw new IllegalStateException(
                    "Unknown version for v= (expected DKIM1): " + getValue("v"));
        if ("".equals(getValue("p")))
            throw new IllegalStateException("Revoked key. 'p=' in record");
        if (isStrictValidation()) {
            // a malformed list is a key syntax error (RFC 6376 section 6.1.2)
            getServiceTypes();
            getAcceptableHashMethods();
            getAcceptableKeyTypes();
            getFlags();
        }
    }

    /**
     * RFC 6376 section 3.6.1, s=: the service types the key may be used for.
     *
     * @return the listed types; with strict validation, an {@link IllegalStateException} on a malformed list
     */
    public List<CharSequence> getServiceTypes() {
        String s = getValue("s").toString();
        if (isStrictValidation()) {
            return stringToColonSeparatedList(s, serviceTypePattern);
        }
        List<CharSequence> res = new ArrayList<>();
        for (String type : s.split(":")) {
            res.add(trimFWS(type, 0, type.length() - 1, true));
        }
        return res;
    }

    /**
     * @see org.apache.james.jdkim.api.PublicKeyRecord#isServiceTypeSupported(java.lang.CharSequence)
     */
    public boolean isServiceTypeSupported(CharSequence serviceType) {
        List<CharSequence> types = getServiceTypes();
        return isInListCaseInsensitive("*", types) || isInListCaseInsensitive(serviceType, types);
    }

    /**
     * @see org.apache.james.jdkim.api.PublicKeyRecord#isHashMethodSupported(java.lang.CharSequence)
     */
    public boolean isHashMethodSupported(CharSequence hash) {
        List<CharSequence> hashes = getAcceptableHashMethods();
        return hashes == null || isInListCaseInsensitive(hash, hashes);
    }

    /**
     * @see org.apache.james.jdkim.api.PublicKeyRecord#isKeyTypeSupported(java.lang.CharSequence)
     */
    public boolean isKeyTypeSupported(CharSequence hash) {
        List<CharSequence> hashes = getAcceptableKeyTypes();
        return isInListCaseInsensitive(hash, hashes);
    }

    /**
     * @see org.apache.james.jdkim.api.PublicKeyRecord#getAcceptableHashMethods()
     */
    public List<CharSequence> getAcceptableHashMethods() {
        if (ANY.equals(getValue("h")))
            return null;
        return stringToColonSeparatedList(getValue("h").toString(),
                hyphenatedWordPattern);
    }

    /**
     * @see org.apache.james.jdkim.api.PublicKeyRecord#getAcceptableKeyTypes()
     */
    public List<CharSequence> getAcceptableKeyTypes() {
        return stringToColonSeparatedList(getValue("k").toString(),
                hyphenatedWordPattern);
    }

    /**
     * @see org.apache.james.jdkim.api.PublicKeyRecord#getGranularityPattern()
     */
    public Pattern getGranularityPattern() {
        String g = getValue("g").toString();
        int pStar = g.indexOf('*');
        if (VALIDATION) {
            if (!granularityPattern.matcher(g).matches())
                throw new IllegalStateException("Syntax error in granularity: "
                        + g);
        }
        if (g.isEmpty()) {
            // TODO this works but smells too much as an hack.
            // in case of "g=" with nothing specified then we return a pattern
            // that won't match
            // SPEC: An empty "g=" value never matches any addresses.
            return Pattern.compile("@");
        } else if (pStar != -1) {
            if (g.indexOf('*', pStar + 1) != -1)
                throw new IllegalStateException(
                        "Invalid granularity using more than one wildcard: "
                                + g);
            // DOTALL: the wildcard matches any local part, line terminators included
            String pattern = "^" + Pattern.quote(g.substring(0, pStar))
                    + ".*" + Pattern.quote(g.substring(pStar + 1)) + "$";
            return Pattern.compile(pattern, Pattern.DOTALL);
        } else {
            return Pattern.compile("^" + Pattern.quote(g) + "$");
        }
    }

    public List<CharSequence> getFlags() {
        String flags = getValue("t").toString();
        if (isStrictValidation() && containsTag("t")) {
            // SPEC: key-t-tag-flag *( [FWS] ":" [FWS] key-t-tag-flag ), each a hyphenated-word
            return stringToColonSeparatedList(flags, hyphenatedWordPattern);
        }
        String[] flagsStrings = flags.split(":");
        List<CharSequence> res = new ArrayList<>();
        for (String flagsString : flagsStrings) {
            res.add(trimFWS(flagsString, 0, flagsString.length() - 1,
                    true));
        }
        return res;
    }

    public boolean isDenySubdomains() {
        return getFlags().contains("s");
    }

    public boolean isTesting() {
        return getFlags().contains("y");
    }

    /**
     * @see org.apache.james.jdkim.api.PublicKeyRecord#getPublicKey()
     */
    public PublicKey getPublicKey() {
        try {
            // only rsa-* signatures are implemented: never let DNS data pick the KeyFactory
            if (!"rsa".equalsIgnoreCase(getValue("k").toString()))
                throw new IllegalStateException("Unsupported key type: " + getValue("k"));
            byte[] key = decodeBase64(getValue("p"));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(key);
            PublicKey publicKey = keyFactory.generatePublic(pubSpec);
            if (!(publicKey instanceof RSAPublicKey))
                throw new IllegalStateException("Not an RSA key: " + publicKey.getAlgorithm());
            return publicKey;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unknown algorithm: "
                    + e.getMessage());
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException("Invalid key spec: "
                    + e.getMessage());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Invalid key encoding: "
                    + e.getMessage());
        }
    }

}
