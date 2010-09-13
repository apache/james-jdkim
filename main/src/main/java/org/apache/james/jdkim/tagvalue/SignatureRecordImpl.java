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

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.Base64;
import org.apache.james.jdkim.api.SignatureRecord;

public class SignatureRecordImpl extends TagValue implements SignatureRecord {

    // TODO ftext is defined as a sequence of at least one in %d33-57 or
    // %d59-126
    private static Pattern hdrNamePattern = Pattern.compile("^[^: \r\n\t]+$");

    public SignatureRecordImpl(String data) {
        super(data);
    }

    protected void init() {
        mandatoryTags.add("v");
        mandatoryTags.add("a");
        mandatoryTags.add("b");
        mandatoryTags.add("bh");
        mandatoryTags.add("d");
        mandatoryTags.add("h");
        mandatoryTags.add("s");

        defaults.put("c", SIMPLE+"/"+SIMPLE);
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
        
        CharSequence identity;
        try {
            identity = getIdentity();
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Identity (i=) declaration cannot be parsed. Probably due to missing quoted printable encoding", e);
        }
        
        if (!identity.toString().toLowerCase().endsWith(
                ("@" + getValue("d")).toLowerCase())
                && !getIdentity().toString().toLowerCase().endsWith(
                        ("." + getValue("d")).toLowerCase()))
            throw new IllegalStateException("Identity (i=) domain mismatch: expected [optional]@[optional.]domain-from-d-attribute");

        // when "x=" exists and signature expired then return PERMFAIL
        // (signature expired)
        if (getValue("x") != null) {
            long expiration = Long.parseLong(getValue("x").toString());
            long lifetime = (expiration - System.currentTimeMillis()/1000);
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
        String lifetimeMeasure = lifetime + measure;
        return lifetimeMeasure;
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
        int pAt = identity.indexOf('@');
        return identity.subSequence(0, pAt);
    }

    /**
     * This may throws IllegalArgumentException on invalid "i" content,
     * but should always happen during validation!
     * 
     * @see org.apache.james.jdkim.api.SignatureRecord#getIdentity()
     */
    public CharSequence getIdentity() {
        return dkimQuotedPrintableDecode(getValue("i"));
    }

    public static String dkimQuotedPrintableDecode(CharSequence input)
            throws IllegalArgumentException {
        StringBuffer sb = new StringBuffer(input.length());
        // TODO should we fail on WSP that is not part of FWS?
        // the specification in 2.6 DKIM-Quoted-Printable is not
        // clear
        int state = 0;
        int start = 0;
        int d = 0;
        boolean lastWasNL = false;
        for (int i = 0; i < input.length(); i++) {
            if (lastWasNL && input.charAt(i) != ' ' && input.charAt(i) != '\t') {
                throw new IllegalArgumentException(
                        "Unexpected LF not part of an FWS");
            }
            lastWasNL = false;
            switch (state) {
            case 0:
                switch (input.charAt(i)) {
                case ' ':
                case '\t':
                case '\r':
                case '\n':
                    if ('\n' == input.charAt(i))
                        lastWasNL = true;
                    sb.append(input.subSequence(start, i));
                    start = i + 1;
                    // ignoring whitespace by now.
                    break;
                case '=':
                    sb.append(input.subSequence(start, i));
                    state = 1;
                    break;
                }
                break;
            case 1:
            case 2:
                if (input.charAt(i) >= '0' && input.charAt(i) <= '9'
                        || input.charAt(i) >= 'A' && input.charAt(i) <= 'F') {
                    int v = Arrays.binarySearch("0123456789ABCDEF".getBytes(),
                            (byte) input.charAt(i));
                    if (state == 1) {
                        state = 2;
                        d = v;
                    } else {
                        d = d * 16 + v;
                        sb.append((char) d);
                        state = 0;
                        start = i + 1;
                    }
                } else {
                    throw new IllegalArgumentException(
                            "Invalid input sequence at " + i);
                }
            }
        }
        if (state != 0) {
            throw new IllegalArgumentException(
                    "Invalid quoted printable termination");
        }
        sb.append(input.subSequence(start, input.length()));
        return sb.toString();
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
        return Base64.decodeBase64(getValue("bh").toString().getBytes());
    }

    public byte[] getSignature() {
        return Base64.decodeBase64(getValue("b").toString().getBytes());
    }

    public int getBodyHashLimit() {
        String limit = getValue("l").toString();
        if (ALL.equals(limit))
            return -1;
        else
            return Integer.parseInt(limit);
    }

    public Long getSignatureTimestamp() {
        CharSequence cs = getValue("t");
        if (cs == null) return null;
        return Long.valueOf(Long.parseLong(cs.toString()));
    }

    public String getBodyCanonicalisationMethod() {
        String c = getValue("c").toString();
        int pSlash = c.toString().indexOf("/");
        if (pSlash != -1) {
            return c.substring(pSlash + 1);
        } else {
            return SIMPLE;
        }
    }

    public String getHeaderCanonicalisationMethod() {
        String c = getValue("c").toString();
        int pSlash = c.toString().indexOf("/");
        if (pSlash != -1) {
            return c.substring(0, pSlash);
        } else {
            return c;
        }
    }

    public List<CharSequence> getRecordLookupMethods() {
        String flags = getValue("q").toString();
        String[] flagsStrings = flags.split(":");
        List<CharSequence> res = new LinkedList<CharSequence>();
        for (int i = 0; i < flagsStrings.length; i++) {
            // TODO add validation method[/option]
            // if (VALIDATION)
            res.add(trimFWS(flagsStrings[i], 0, flagsStrings[i].length() - 1,
                    true));
        }
        return res;
    }

    public void setSignature(byte[] newSignature) {
        String signature = new String(Base64.encodeBase64(newSignature));
        setValue("b", signature);
    }

    public void setBodyHash(byte[] newBodyHash) {
        String bodyHash = new String(Base64.encodeBase64(newBodyHash));
        setValue("bh", bodyHash);
        // If a t=; parameter is present in the signature, make sure to 
        // fill it with the current timestamp
        if (getValue("t") != null && getValue("t").toString().trim().length() == 0) {
            setValue("t", ""+(System.currentTimeMillis() / 1000));
        }
    }

    public String toUnsignedString() {
        return toString().replaceFirst("b=[^;]*", "b=");
    }
}
