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

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.Base64;
import org.apache.james.jdkim.PublicKeyRecord;
import org.apache.james.jdkim.SignatureRecord;

public class PublicKeyRecordImpl extends TagValue implements PublicKeyRecord {
	
	private static final String atom = "[a-zA-Z0-9!#$%&'*+/=?^_`{}|~-]+";
	// TODO this should support CFWS: are they supported in DKIM for real?
	private static final String dotAtomText = "("+atom+")?\\*?("+atom+")?";
	private static final Pattern granularityPattern = Pattern.compile("^"+dotAtomText+"$");

	// SPEC: hyphenated-word =  ALPHA [ *(ALPHA / DIGIT / "-") (ALPHA / DIGIT) ]
	private static Pattern hyphenatedWordPattern = Pattern.compile("^[a-zA-Z]([a-zA-Z0-9-]*[a-zA-Z0-9])?$");

	public PublicKeyRecordImpl(String data) {
		super(data);
	}
	
	protected void init() {
		// extensions may override this to use TreeMaps in order to keep track of orders
		tagValues = new LinkedHashMap();
		mandatoryTags.add("p");
		defaults.put("v", "DKIM1");
		defaults.put("g", "*");
		defaults.put("h", ANY);
		defaults.put("k", "rsa");
		defaults.put("s", "*");
		defaults.put("t", "");
	}
	
	// TODO do we treat v=NONDKIM1 records, syntax error records and v=DKIM1 in the middle records
	//       in the same way?
	public void validate() {
		super.validate();
		if (tagValues.containsKey("v")) {
			// if "v" is specified it must be the first tag
			String firstKey = (String) ((LinkedHashMap) tagValues).keySet().iterator().next();
			if (!"v".equals(firstKey)) throw new IllegalStateException("Existing v= tag MUST be the first in the record list ("+firstKey+")");
		}
		if (!"DKIM1".equals(getValue("v"))) throw new IllegalStateException("Unknown version for v= (expected DKIM1): "+getValue("v"));
		if ("".equals(getValue("p"))) throw new IllegalStateException("Revoked key. 'p=' in record");
	}

	/**
	 * @see org.apache.james.jdkim.PublicKeyRecord#isHashMethodSupported(java.lang.CharSequence)
	 */
	public boolean isHashMethodSupported(CharSequence hash) {
		List hashes = getAcceptableHashMethods();
		if (hashes == null) return true;
		return isInListCaseInsensitive(hash, hashes);
	}

	/**
	 * @see org.apache.james.jdkim.PublicKeyRecord#isKeyTypeSupported(java.lang.CharSequence)
	 */
	public boolean isKeyTypeSupported(CharSequence hash) {
		List hashes = getAcceptableKeyTypes();
		return isInListCaseInsensitive(hash, hashes);
	}
	
	/**
	 * @see org.apache.james.jdkim.PublicKeyRecord#getAcceptableHashMethods()
	 */
	public List/* String */ getAcceptableHashMethods() {
		if (ANY.equals(getValue("h"))) return null;
		return stringToColonSeparatedList(getValue("h").toString(), hyphenatedWordPattern);
	}
	/**
	 * @see org.apache.james.jdkim.PublicKeyRecord#getAcceptableKeyTypes()
	 */
	public List/* String */ getAcceptableKeyTypes() {
		return stringToColonSeparatedList(getValue("k").toString(), hyphenatedWordPattern);
	}


	/**
	 * @see org.apache.james.jdkim.PublicKeyRecord#getGranularityPattern()
	 */
	public Pattern getGranularityPattern() {
		String g = getValue("g").toString();
		int pStar = g.indexOf('*');
		if (VALIDATION) {
			if (!granularityPattern.matcher(g).matches()) throw new IllegalStateException("Syntax error in granularity: "+g);
		}
		if (g.length() == 0) {
			// TODO this works but smells too much as an hack.
			// in case of "g=" with nothing specified then we return a pattern that won't match
			// SPEC: An empty "g=" value never matches any addresses.
			return Pattern.compile("@");
		} else if (pStar != -1) {
			if (g.indexOf('*',pStar+1) != -1) throw new IllegalStateException("Invalid granularity using more than one wildcard: "+g);
			String pattern = "^"+Pattern.quote(g.subSequence(0, pStar).toString())+".*"+Pattern.quote(g.subSequence(pStar+1, g.length()).toString())+"$";
			return Pattern.compile(pattern);
		} else {
			return Pattern.compile("^"+Pattern.quote(g)+"$");
		}
	}

	public List getFlags() {
		String flags = getValue("t").toString();
		String[] flagsStrings = flags.split(":");
		List res = new ArrayList();
		for (int i = 0; i < flagsStrings.length; i++) {
			res.add(trimFWS(flagsStrings[i], 0, flagsStrings[i].length()-1, true).toString());
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
	 * @see org.apache.james.jdkim.PublicKeyRecord#getPublicKey()
	 */
	public PublicKey getPublicKey() {
		try {
			String p = getValue("p").toString();
			byte[] key = Base64.decodeBase64( p.getBytes() );
			KeyFactory keyFactory;
			keyFactory = KeyFactory.getInstance(getValue("k").toString());
			X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(key);
			RSAPublicKey rsaKey;
			rsaKey = (RSAPublicKey) keyFactory.generatePublic(pubSpec);
			return rsaKey;
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Unknown algorithm",e);
		} catch (InvalidKeySpecException e) {
			throw new IllegalStateException("Invalid key spec",e);
		}
	}

	/**
	 * @see org.apache.james.jdkim.PublicKeyRecord#apply(org.apache.james.jdkim.SignatureRecord)
	 */
	public void apply(SignatureRecord sign) {
		if (!getGranularityPattern().matcher(sign.getIdentityLocalPart()).matches()) {
			throw new IllegalStateException("inapplicable key for g="+getValue("g")+" and identity local="+sign.getIdentityLocalPart()+" Pattern: "+getGranularityPattern().pattern());
		}
		
		if (!isHashMethodSupported(sign.getHashMethod())) {
			throw new IllegalStateException("inappropriate hash method h="+getValue("h")+" and a="+sign.getHashKeyType()+"/"+sign.getHashMethod());
		}
		if (!isKeyTypeSupported(sign.getHashKeyType())) {
			throw new IllegalStateException("inappropriate key type k="+getValue("k")+" and a="+sign.getHashKeyType()+"/"+sign.getHashMethod());
		}
		
		if (isDenySubdomains()) {
			if (!sign.getIdentity().toString().toLowerCase().endsWith(("@"+sign.getDToken()).toLowerCase())) {
				throw new IllegalStateException("AUID in subdomain of SDID is not allowed by the public key record.");
			}
		}
		
	}

}
