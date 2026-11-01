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

import static org.apache.james.jdkim.parser.DKIMQuotedPrintable.dkimQuotedPrintableDecode;

import org.apache.james.jdkim.api.HashMethod;
import org.apache.james.jdkim.api.SignatureRecord;

import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class SignatureRecordImpl extends TagValue implements SignatureRecord {

    /**
     * RFC 6376 section 3.3: the a= values, case-sensitive (section 3.2), and their hash method.
     */
    private static final Map<String, HashMethod> ALGORITHMS;

    static {
        Map<String, HashMethod> algorithms = new LinkedHashMap<>();
        algorithms.put("rsa-sha256", HashMethod.SHA256);
        algorithms.put("rsa-sha1", HashMethod.SHA1);
        ALGORITHMS = Collections.unmodifiableMap(algorithms);
    }

    /**
     * Checks an a= value against the algorithms of RFC 6376 section 3.3.
     *
     * @param algorithm the a= value
     * @return its hash method
     * @throws IllegalStateException if it is not rsa-sha256 or rsa-sha1, exactly
     */
    public static HashMethod checkAlgorithm(CharSequence algorithm) {
        HashMethod hashMethod = algorithm == null ? null : ALGORITHMS.get(algorithm.toString());
        if (hashMethod == null) {
            throw new IllegalStateException("Unsupported signature algorithm (a=): " + algorithm
                    + ", expected one of " + ALGORITHMS.keySet());
        }
        return hashMethod;
    }

    // SPEC: sub-domain = Let-dig [Ldh-str] (RFC 5321), at most 63 octets (RFC 1035)
    private static final Pattern SUB_DOMAIN = Pattern.compile("[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?");
    private static final int MAX_DOMAIN_NAME_LENGTH = 253;

    /**
     * RFC 6376 section 3.5: checks d= (domain-name = sub-domain 1*("." sub-domain)), s= (selector =
     * sub-domain *("." sub-domain)) and that the key query name s._domainkey.d fits in 253 octets.
     * Only with strict validation, see {@link TagValue#isStrictValidation()}.
     *
     * @throws IllegalStateException if they do not
     */
    static void checkSdidAndSelector(CharSequence d, CharSequence selector) {
        if (!isStrictValidation()) {
            return;
        }
        checkDomainName("d=", d.toString(), 2);
        checkDomainName("s=", selector.toString(), 1);
        int queryNameLength = selector.length() + "._domainkey.".length() + d.length();
        if (queryNameLength > MAX_DOMAIN_NAME_LENGTH) {
            throw new IllegalStateException("Key query name s._domainkey.d is " + queryNameLength
                    + " octets long, over " + MAX_DOMAIN_NAME_LENGTH);
        }
    }

    /**
     * @param what the tag, for the error message
     * @param name the name to check as sub-domain *("." sub-domain)
     * @param minLabels the minimum number of labels
     * @throws IllegalStateException if it is not a valid name
     */
    static void checkDomainName(String what, String name, int minLabels) {
        String[] labels = name.split("\\.", -1);
        if (labels.length < minLabels) {
            throw new IllegalStateException("Invalid " + what + " [" + name + "]: at least " + minLabels + " labels expected");
        }
        for (String label : labels) {
            if (!SUB_DOMAIN.matcher(label).matches()) {
                throw new IllegalStateException("Invalid " + what + " [" + name + "]: label [" + label
                        + "] is not a sub-domain (RFC 6376 section 3.5)");
            }
        }
        if (name.length() > MAX_DOMAIN_NAME_LENGTH) {
            throw new IllegalStateException("Invalid " + what + " [" + name + "]: over " + MAX_DOMAIN_NAME_LENGTH + " octets");
        }
    }

    // SPEC (RFC 5321): Dot-string = Atom *("." Atom) ; Quoted-string = DQUOTE *QcontentSMTP DQUOTE,
    // with the non-ASCII characters RFC 6531 adds to atext and qtextSMTP
    private static final String ATEXT = "[A-Za-z0-9!#$%&'*+/=?^_`{|}~\\u0080-\\uFFFF-]+";
    private static final Pattern LOCAL_PART = Pattern.compile(
            "|" + ATEXT + "(?:\\." + ATEXT + ")*|\"(?:[\\x20\\x21\\x23-\\x5B\\x5D-\\x7E\\u0080-\\uFFFF]|\\\\[\\x20-\\x7E])*\"");

    /**
     * RFC 6376 section 3.5: checks the decoded i= value as [ Local-part ] "@" domain-name.
     * Only with strict validation, see {@link TagValue#isStrictValidation()}.
     *
     * @throws IllegalStateException if it is not
     */
    static void checkIdentity(CharSequence identity) {
        if (!isStrictValidation()) {
            return;
        }
        String value = identity.toString();
        int at = value.lastIndexOf('@');
        if (at == -1) {
            throw new IllegalStateException("Invalid i= [" + value + "]: no @");
        }
        String localPart = value.substring(0, at);
        if (!LOCAL_PART.matcher(localPart).matches()) {
            throw new IllegalStateException("Invalid i= [" + value + "]: the local part is neither a Dot-string"
                    + " nor a Quoted-string (RFC 5321)");
        }
        checkDomainName("i= domain", value.substring(at + 1), 2);
    }

    /**
     * Checks the a= value of a signature record, see {@link #checkAlgorithm(CharSequence)}.
     *
     * @param sign a signature record
     * @return its hash method
     */
    public static HashMethod checkAlgorithm(SignatureRecord sign) {
        return checkAlgorithm(sign.getHashKeyType() + "-" + sign.getHashMethod());
    }

    // TODO ftext is defined as a sequence of at least one in %d33-57 or
    // %d59-126
    private static final Pattern hdrNamePattern = Pattern.compile("^[^: \r\n\t]+$");
    private static final Pattern timestampPattern = Pattern.compile("^[0-9]{1,12}$");
    private static final Pattern bodyLengthPattern = Pattern.compile("^[0-9]{1,76}$");

    public SignatureRecordImpl(String data) {
        super(data);
        validate();
    }

    protected void init() {
        mandatoryTags.add("v");
        mandatoryTags.add("a");
        mandatoryTags.add("b");
        mandatoryTags.add("bh");
        mandatoryTags.add("d");
        mandatoryTags.add("h");
        mandatoryTags.add("s");

        defaults.put("c", SIMPLE + "/" + SIMPLE);
        defaults.put("l", ALL);
        defaults.put("q", "dns/txt");
    }

    /**
     * @see org.apache.james.jdkim.api.SignatureRecord#validate()
     */
    public void validate() throws IllegalStateException {
        super.validate();
        // TODO: what about v=0.5 and no v= at all?
        // do specs allow parsing? what should we check?
        if (!"1".equals(getValue("v")))
            throw new IllegalStateException(
                    "Invalid DKIM-Signature version (expected '1'): "
                            + getValue("v"));
        if (getValue("h").length() == 0)
            throw new IllegalStateException("Tag h= cannot be empty.");

        checkAlgorithm(getValue("a"));
        checkSdidAndSelector(getValue("d"), getValue("s"));

        CharSequence identity;
        try {
            identity = getIdentity();
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Identity (i=) declaration cannot be parsed. Probably due to missing quoted printable encoding", e);
        }

        checkIdentity(identity.toString(), getValue("d").toString());

        // RFC 6376 section 3.5: sig-t-tag = %x74 [FWS] "=" [FWS] 1*12DIGIT
        if (getValue("t") != null && !timestampPattern.matcher(getValue("t")).matches())
            throw new IllegalStateException("Invalid signature timestamp (t=): " + getValue("t"));

        // RFC 6376 section 3.5: sig-l-tag = %x6c [FWS] "=" [FWS] 1*76DIGIT
        if (!ALL.equals(getValue("l")) && !bodyLengthPattern.matcher(getValue("l")).matches())
            throw new IllegalStateException("Invalid body length (l=): " + getValue("l"));

        // RFC 6376 section 3.5: x= MUST be greater than t= if both are present
        if (getValue("x") != null && timestampPattern.matcher(getValue("x")).matches() && getValue("t") != null
                && Long.parseLong(getValue("x").toString()) <= Long.parseLong(getValue("t").toString()))
            throw new IllegalStateException("Signature expiration (x=) must be greater than its timestamp (t=)");

        checkIdentity(identity);

        // when "x=" exists and signature expired then return PERMFAIL
        // (signature expired)
        if (getValue("x") != null) {
            // RFC 6376 section 3.5: sig-x-tag = %x78 [FWS] "=" [FWS] 1*12DIGIT
            if (!timestampPattern.matcher(getValue("x")).matches())
                throw new IllegalStateException("Invalid expiration (x=): " + getValue("x"));
            long expiration = Long.parseLong(getValue("x").toString());
            long lifetime = (expiration - System.currentTimeMillis() / 1000);
            if (lifetime < 0) {
                throw new IllegalStateException("Signature is expired since "
                        + getTimeMeasure(lifetime) + ".");
            }
        }

        // when "h=" does not contain "from" return PERMFAIL (From field not
        // signed).
        if (!isInListCaseInsensitive("from", getHeaders()))
            throw new IllegalStateException("From field not signed");
        // TODO support ignoring signature for certain d values (externally to
        // this class).
    }

    /**
     * RFC 6376 section 3.5: sig-i-tag = [ Local-part ] "@" domain-name, the
     * domain being d= or one of its subdomains.
     */
    static void checkIdentity(String identity, String d) {
        String domain = identity.substring(identityAt(identity) + 1);
        // regionMatches compares case-insensitively without the default locale
        boolean sameDomain = domain.length() == d.length() && domain.regionMatches(true, 0, d, 0, d.length());
        boolean subDomain = domain.length() > d.length()
                && domain.charAt(domain.length() - d.length() - 1) == '.'
                && domain.regionMatches(true, domain.length() - d.length(), d, 0, d.length());
        if (!sameDomain && !subDomain)
            throw new IllegalStateException("Identity (i=) domain mismatch: expected [optional]@[optional.]domain-from-d-attribute");
    }

    /**
     * @return the position of the single '@' of the identity
     */
    static int identityAt(String identity) {
        int pAt = identity.indexOf('@');
        if (pAt == -1 || identity.indexOf('@', pAt + 1) != -1)
            throw new IllegalStateException("Identity (i=) must contain exactly one '@': " + identity);
        return pAt;
    }

    private String getTimeMeasure(long lifetime) {
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

    /**
     * @see org.apache.james.jdkim.api.SignatureRecord#getHeaders()
     */
    public List<CharSequence> getHeaders() {
        return stringToColonSeparatedList(getValue("h").toString(),
                hdrNamePattern);
    }

    // If i= is unspecified the default is @d
    protected CharSequence getDefault(String tag) {
        if ("i".equals(tag)) {
            return "@" + getValue("d");
        } else
            return super.getDefault(tag);
    }

    /**
     * @see org.apache.james.jdkim.api.SignatureRecord#getIdentityLocalPart()
     */
    public CharSequence getIdentityLocalPart() {
        String identity = getIdentity().toString();
        return identity.substring(0, identityAt(identity));
    }

    /**
     * This may throws IllegalArgumentException on invalid "i" content,
     * but should always happen during validation!
     *
     * @see org.apache.james.jdkim.api.SignatureRecord#getIdentity()
     */
    public CharSequence getIdentity() {
        // the default identity is built from d=, it is not DKIM-Quoted-Printable
        if (!containsTag("i"))
            return getValue("i");
        return dkimQuotedPrintableDecode(getValue("i"));
    }

    /**
     * @see org.apache.james.jdkim.api.SignatureRecord#getHashKeyType()
     */
    public CharSequence getHashKeyType() {
        String a = getValue("a").toString();
        int pHyphen = a.indexOf('-');
        // TODO x-sig-a-tag-h = ALPHA *(ALPHA / DIGIT)
        if (pHyphen == -1)
            throw new IllegalStateException(
                    "Invalid hash algorythm (key type): " + a);
        return a.subSequence(0, pHyphen);
    }

    /**
     * @see org.apache.james.jdkim.api.SignatureRecord#getHashMethod()
     */
    public CharSequence getHashMethod() {
        String a = getValue("a").toString();
        int pHyphen = a.indexOf('-');
        // TODO x-sig-a-tag-h = ALPHA *(ALPHA / DIGIT)
        if (pHyphen == -1)
            throw new IllegalStateException("Invalid hash method: " + a);
        return a.subSequence(pHyphen + 1, a.length());
    }

    /**
     * @see org.apache.james.jdkim.api.SignatureRecord#getHashAlgo()
     */
    public CharSequence getHashAlgo() {
        String a = getValue("a").toString();
        int pHyphen = a.indexOf('-');
        if (pHyphen == -1)
            throw new IllegalStateException("Invalid hash method: " + a);
        if (a.length() > pHyphen + 3 && a.charAt(pHyphen + 1) == 's'
                && a.charAt(pHyphen + 2) == 'h' && a.charAt(pHyphen + 3) == 'a') {
            return "sha-" + a.subSequence(pHyphen + 4, a.length());
        } else
            return a.subSequence(pHyphen + 1, a.length());
    }

    /**
     * @see org.apache.james.jdkim.api.SignatureRecord#getSelector()
     */
    public CharSequence getSelector() {
        return getValue("s");
    }

    /**
     * @see org.apache.james.jdkim.api.SignatureRecord#getDToken()
     */
    public CharSequence getDToken() {
        return getValue("d");
    }

    public byte[] getBodyHash() {
        return decodeBase64TagValue("bh");
    }

    public byte[] getSignature() {
        return decodeBase64TagValue("b");
    }

    public CharSequence getRawSignature() {
        return getValue("b");
    }

    public int getBodyHashLimit() {
        String limit = getValue("l").toString();
        if (ALL.equals(limit))
            return -1;
        else
            return parseBodyHashLimit(limit);
    }

    /**
     * Parses a validated l= value. Values beyond Integer.MAX_VALUE exceed any
     * body we can hash and are clamped.
     */
    static int parseBodyHashLimit(String limit) {
        String digits = limit.replaceFirst("^0+(?=.)", "");
        if (digits.length() > 10)
            return Integer.MAX_VALUE;
        return (int) Math.min(Long.parseLong(digits), Integer.MAX_VALUE);
    }

    public Long getSignatureTimestamp() {
        CharSequence cs = getValue("t");
        if (cs == null) return null;
        return Long.parseLong(cs.toString());
    }

    public String getBodyCanonicalisationMethod() {
        String c = getValue("c").toString();
        int pSlash = c.indexOf("/");
        if (pSlash != -1) {
            return c.substring(pSlash + 1);
        } else {
            return SIMPLE;
        }
    }

    public String getHeaderCanonicalisationMethod() {
        String c = getValue("c").toString();
        int pSlash = c.indexOf("/");
        if (pSlash != -1) {
            return c.substring(0, pSlash);
        } else {
            return c;
        }
    }

    public List<CharSequence> getRecordLookupMethods() {
        String flags = getValue("q").toString();
        String[] flagsStrings = flags.split(":");
        List<CharSequence> res = new LinkedList<>();
        for (String flagsString : flagsStrings) {
            // TODO add validation method[/option]
            // if (VALIDATION)
            res.add(trimFWS(flagsString, 0, flagsString.length() - 1,
                    true));
        }
        return res;
    }

    public void setSignature(byte[] newSignature) {
        String signature = Base64.getEncoder().encodeToString(newSignature);
        setValue("b", signature);
    }

    public void setBodyHash(byte[] newBodyHash) {
        String bodyHash = Base64.getEncoder().encodeToString(newBodyHash);
        setValue("bh", bodyHash);
        // If a t=; parameter is present in the signature, make sure to 
        // fill it with the current timestamp
        if (getValue("t") != null && getValue("t").toString().trim().isEmpty()) {
            setValue("t", "" + (System.currentTimeMillis() / 1000));
        }
    }

    @Override
    protected boolean isFoldedRepresentation() {
        return true;
    }

    public String toUnsignedString() {
        return emptyTagValue(toString(), "b");
    }
}
