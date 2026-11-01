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

import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import org.apache.james.jdkim.api.HashMethod;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.api.SigningAlgorithm;
import org.apache.james.jdkim.parser.DKIMQuotedPrintable;

public class SignatureRecordTemplate extends TagValue implements SignatureRecord {

    // TODO ftext is defined as a sequence of at least one in %d33-57 or
    // %d59-126
    private static final Pattern hdrNamePattern = Pattern.compile("^[^: \r\n\t]+$");
    private static final Pattern timestampPattern = Pattern.compile("^[0-9]{1,12}$");
    private static final Pattern bodyLengthPattern = Pattern.compile("^[0-9]{1,76}$");

    public SignatureRecordTemplate(String data) {
        super(data);
        validate();
        Set<String> tags = getTags();
        defaults.forEach((key, value) -> {
                    if (!tags.contains(key) && !"l".equals(key)) {
                        setValue(key, value.toString());
                    }
                }
        );
    }

    protected void init() {
        mandatoryTags.add("v");
        mandatoryTags.add("d");
        mandatoryTags.add("h");
        mandatoryTags.add("s");

        defaults.put("b", "");
        defaults.put("bh", "");
        defaults.put("c", SIMPLE + "/" + SIMPLE);
        defaults.put("l", ALL);
        defaults.put("q", "dns/txt");
    }

    /**
     * @see SignatureRecord#validate()
     */
    public void validate() throws IllegalStateException {
        super.validate();
        if (getValue("a") != null) {
            SignatureRecordImpl.checkAlgorithm(getValue("a"));
        }
        // TODO: what about v=0.5 and no v= at all?
        // do specs allow parsing? what should we check?
        if (!"1".equals(getValue("v")))
            throw new IllegalStateException(
                    "Invalid DKIM-Signature version (expected '1'): "
                            + getValue("v"));
        if (getValue("h").length() == 0)
            throw new IllegalStateException("Tag h= cannot be empty.");

        CharSequence identity;
        try {
            identity = getIdentity();
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Identity (i=) declaration cannot be parsed. Probably due to missing quoted printable encoding", e);
        }

        SignatureRecordImpl.checkIdentity(identity.toString(), getValue("d").toString());

        // An empty t= asks the signer to fill in the signing time.
        if (getValue("t") != null && getValue("t").length() > 0
                && !timestampPattern.matcher(getValue("t")).matches())
            throw new IllegalStateException("Invalid signature timestamp (t=): " + getValue("t"));

        // RFC 6376 section 3.5: sig-l-tag = %x6c [FWS] "=" [FWS] 1*76DIGIT
        if (!ALL.equals(getValue("l")) && !bodyLengthPattern.matcher(getValue("l")).matches())
            throw new IllegalStateException("Invalid body length (l=): " + getValue("l"));

        // RFC 6376 section 3.5: x= MUST be greater than t= if both are present
        if (getValue("x") != null && timestampPattern.matcher(getValue("x")).matches() && getValue("t") != null && getValue("t").length() > 0
                && Long.parseLong(getValue("x").toString()) <= Long.parseLong(getValue("t").toString()))
            throw new IllegalStateException("Signature expiration (x=) must be greater than its timestamp (t=)");

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
     * @see SignatureRecord#getHeaders()
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
     * @see SignatureRecord#getIdentityLocalPart()
     */
    public CharSequence getIdentityLocalPart() {
        String identity = getIdentity().toString();
        return identity.substring(0, SignatureRecordImpl.identityAt(identity));
    }

    /**
     * This may throws IllegalArgumentException on invalid "i" content,
     * but should always happen during validation!
     *
     * @see SignatureRecord#getIdentity()
     */
    public CharSequence getIdentity() {
        // the default identity is built from d=, it is not DKIM-Quoted-Printable
        if (!containsTag("i"))
            return getValue("i");
        return DKIMQuotedPrintable.dkimQuotedPrintableDecode(getValue("i"));
    }

    /**
     * @see SignatureRecord#getHashKeyType()
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
     * @see SignatureRecord#getHashMethod()
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
     * @see SignatureRecord#getHashAlgo()
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
     * @see SignatureRecord#getSelector()
     */
    public CharSequence getSelector() {
        return getValue("s");
    }

    /**
     * @see SignatureRecord#getDToken()
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
            return SignatureRecordImpl.parseBodyHashLimit(limit);
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
        String signature = new String(Base64.getEncoder().encode(newSignature));
        setValue("b", signature);
    }

    public void setBodyHash(byte[] newBodyHash) {
        String bodyHash = new String(Base64.getEncoder().encode(newBodyHash));
        setValue("bh", bodyHash);
        // If a t=; parameter is present in the signature, make sure to 
        // fill it with the current timestamp
        if (getValue("t") != null && getValue("t").toString().trim().isEmpty()) {
            setValue("t", "" + (System.currentTimeMillis() / 1000));
        }
    }

    public SignatureRecordImpl toSignatureRecord(SigningAlgorithm algorithm, HashMethod hashMethod, byte[] bodyHash, byte[] signature) {
        setValue("a", algorithm.asTagValue() + "-" + hashMethod.asTagValue());

        String bodyHashTagValue = new String(Base64.getEncoder().encode(bodyHash));
        setValue("bh", bodyHashTagValue);

        String signatureTagValue = new String(Base64.getEncoder().encode(signature));
        setValue("b", signatureTagValue);
        // If a t=; parameter is present in the signature, make sure to
        // fill it with the current timestamp
        if (getValue("t") != null && getValue("t").toString().trim().isEmpty()) {
            setValue("t", "" + (System.currentTimeMillis() / 1000));
        }
        return new SignatureRecordImpl(this.toString());
    }

    @Override
    protected boolean isFoldedRepresentation() {
        return true;
    }

    public String toUnsignedString() {
        return emptyTagValue(toString(), "b");
    }
}
