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

import java.util.LinkedList;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.james.jdkim.CodecUtil;
import org.apache.james.jdkim.SignatureRecord;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;


public class SignatureRecordImpl extends TagValue implements SignatureRecord {

	// TODO ftext is defined as a sequence of at least one in %d33-57 or %d59-126
	private static Pattern hdrNamePattern = Pattern.compile("^[^: \r\n\t]+$");

	public SignatureRecordImpl(String data) {
		super(data);
	}
	
	protected void init() {
		super.init();
		
		mandatoryTags.add("v");
		mandatoryTags.add("a");
		mandatoryTags.add("b");
		mandatoryTags.add("bh");
		mandatoryTags.add("d");
		mandatoryTags.add("h");
		mandatoryTags.add("s");

		defaults.put("c", "simple/simple");
		defaults.put("l", ALL);
		defaults.put("q", "dns/txt");
	}
	
	/**
	 * @see org.apache.james.jdkim.SignatureRecord#validate()
	 */
	public void validate() throws IllegalStateException {
		super.validate();
		// TODO: what about v=0.5 and no v= at all?
		// do specs allow parsing? what should we check?
		if (!"1".equals(getValue("v"))) throw new IllegalStateException("Invalid DKIM-Signature version (expected '1'): "+getValue("v"));
		if (getValue("h").length() == 0) throw new IllegalStateException("Tag h= cannot be empty.");
		if (!getIdentity().toString().toLowerCase().endsWith(("@"+getValue("d")).toLowerCase())
				&& !getIdentity().toString().toLowerCase().endsWith(("."+getValue("d")).toLowerCase())) throw new IllegalStateException("Domain mismatch");

		// when "x=" exists and signature expired then return PERMFAIL (signature expired)
		if (getValue("x") != null) {
			long expiration = Long.parseLong(getValue("x").toString());
			long lifetime = (expiration - System.currentTimeMillis() / 1000);
			String measure = "s";
			if (lifetime < 0) {
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
								measure =" months";
								if (lifetime > 24) {
									lifetime = lifetime / 12;
									measure = " years";
								}
							}
						}
					}
				}
				throw new IllegalStateException("Signature is expired since "+lifetime+measure+".");
			}
		}
		
		// when "h=" does not contain "from" return PERMFAIL (From field not signed).
		if (!isInListCaseInsensitive("from", getHeaders())) throw new IllegalStateException("From field not signed");
		// TODO support ignoring signature for certain d values (externally to this class).
	}
	
	/**
	 * @see org.apache.james.jdkim.SignatureRecord#getHeaders()
	 */
	public List/* CharSequence */ getHeaders() {
		return stringToColonSeparatedList(getValue("h").toString(), hdrNamePattern);
	}

	// If i= is unspecified the default is @d
	protected CharSequence getDefault(String tag) {
		if ("i".equals(tag)) {
			return "@"+getValue("d");
		} else return super.getDefault(tag);
	}

	/**
	 * @see org.apache.james.jdkim.SignatureRecord#getIdentityLocalPart()
	 */
	public CharSequence getIdentityLocalPart() {
		String identity = getIdentity().toString();
		int pAt = identity.indexOf('@');
		return identity.subSequence(0, pAt);
	}
	
	public CharSequence getIdentity() {
		return CodecUtil.dkimQuotedPrintableDecode(getValue("i"));
	}
	
	/**
	 * @see org.apache.james.jdkim.SignatureRecord#getHashKeyType()
	 */
	public CharSequence getHashKeyType() {
		String a = getValue("a").toString();
		int pHyphen = a.indexOf('-');
		// TODO x-sig-a-tag-h   = ALPHA *(ALPHA / DIGIT)
		if (pHyphen == -1) throw new IllegalStateException("Invalid hash algorythm (key type): "+a);
		return a.subSequence(0, pHyphen);
	}
	
	/**
	 * @see org.apache.james.jdkim.SignatureRecord#getHashMethod()
	 */
	public CharSequence getHashMethod() {
		String a = getValue("a").toString();
		int pHyphen = a.indexOf('-');
		// TODO x-sig-a-tag-h   = ALPHA *(ALPHA / DIGIT)
		if (pHyphen == -1) throw new IllegalStateException("Invalid hash method: "+a);
		return a.subSequence(pHyphen+1, a.length());
	}
	
	/**
	 * @see org.apache.james.jdkim.SignatureRecord#getHashAlgo()
	 */
	public CharSequence getHashAlgo() {
		String a = getValue("a").toString();
		int pHyphen = a.indexOf('-');
		if (pHyphen == -1) throw new IllegalStateException("Invalid hash method: "+a);
		if (a.length() > pHyphen+3 && a.charAt(pHyphen+1) == 's' && a.charAt(pHyphen+2) == 'h' && a.charAt(pHyphen+3) == 'a') {
			return "sha-"+a.subSequence(pHyphen+4, a.length());
		} else return a.subSequence(pHyphen+1, a.length());
	}
	
	/**
	 * @see org.apache.james.jdkim.SignatureRecord#getSelector()
	 */
	public CharSequence getSelector() {
		return getValue("s");
	}

	/**
	 * @see org.apache.james.jdkim.SignatureRecord#getDToken()
	 */
	public CharSequence getDToken() {
		return getValue("d");
	}

	public byte[] getBodyHash() {
		try {
			return Base64.decode(getValue("bh").toString().getBytes());
		} catch (Base64DecodingException e) {
			// TODO not the best thing
			throw new IllegalStateException("Base64.decode.failed", e);
		}
	}

	public byte[] getSignature() {
		try {
			return Base64.decode(getValue("b").toString().getBytes());
		} catch (Base64DecodingException e) {
			// TODO not the best thing
			throw new IllegalStateException("Base64.decode.failed", e);
		}
	}

	public int getBodyHashLimit() {
		String limit = getValue("l").toString();
		if (ALL.equals(limit)) return -1;
		else return Integer.parseInt(limit);
	}

	public String getBodyCanonicalisationMethod() {
		String c = getValue("c").toString();
		int pSlash = c.toString().indexOf("/");
		if (pSlash != -1) {
			return c.substring(pSlash+1);
		} else {
			return "simple";
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
	
	public List getRecordLookupMethods() {
		String flags = getValue("q").toString();
		String[] flagsStrings = flags.split(":");
		List res = new LinkedList();
		for (int i = 0; i < flagsStrings.length; i++) {
			// TODO add validation method[/option]
			// if (VALIDATION)
			res.add(trimFWS(flagsStrings[i], 0, flagsStrings[i].length()-1, true).toString());
		}
		return res;
	}

}
