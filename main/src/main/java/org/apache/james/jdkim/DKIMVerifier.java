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

package org.apache.james.jdkim;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.james.jdkim.api.BodyHasher;
import org.apache.james.jdkim.api.Headers;
import org.apache.james.jdkim.api.PublicKeyRecord;
import org.apache.james.jdkim.api.PublicKeyRecordRetriever;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.canon.CompoundOutputStream;
import org.apache.james.jdkim.exceptions.FailException;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.exceptions.TempFailException;
import org.apache.james.jdkim.impl.BodyHasherImpl;
import org.apache.james.jdkim.impl.DNSPublicKeyRecordRetriever;
import org.apache.james.jdkim.impl.Message;
import org.apache.james.jdkim.impl.MultiplexingPublicKeyRecordRetriever;
import org.apache.james.jdkim.tagvalue.PublicKeyRecordImpl;
import org.apache.james.jdkim.tagvalue.SignatureRecordImpl;
import org.apache.james.mime4j.MimeException;

public class DKIMVerifier extends DKIMCommon {

	private PublicKeyRecordRetriever publicKeyRecordRetriever;

	public DKIMVerifier() {
		this.publicKeyRecordRetriever = new MultiplexingPublicKeyRecordRetriever("dns", new DNSPublicKeyRecordRetriever());
	}
	
	public DKIMVerifier(PublicKeyRecordRetriever publicKeyRecordRetriever) {
		this.publicKeyRecordRetriever = publicKeyRecordRetriever;
	}

	protected PublicKeyRecord newPublicKeyRecord(String record) {
		return new PublicKeyRecordImpl(record);
	}

	public SignatureRecord newSignatureRecord(String record) {
		return new SignatureRecordImpl(record);
	}

	public BodyHasher newBodyHasher(SignatureRecord signRecord) throws NoSuchAlgorithmException {
		return new BodyHasherImpl(signRecord);
	}

	protected PublicKeyRecordRetriever getPublicKeyRecordRetriever() throws PermFailException {
		return publicKeyRecordRetriever;
	}

	public PublicKeyRecord publicKeySelector(List records) throws PermFailException {
		String lastError = null;
		if (records == null || records.size() == 0) {
			lastError = "no key for signature";
		} else {
			for (Iterator i = records.iterator(); i.hasNext();) {
				String record = (String) i.next();
				try {
					PublicKeyRecord pk = newPublicKeyRecord(record);
					pk.validate();
					// we expect a single valid record, otherwise the result
					// is unpredictable.
					// in case of multiple valid records we use the first one.
					return pk;
				} catch (IllegalStateException e) {
					// do this at last.
					lastError = "invalid key for signature: "+e.getMessage();
				}
			}
		}
		// return PERMFAIL ($error).
		throw new PermFailException(lastError);
	}

	/**
	 * @see org.apache.james.jdkim.api.PublicKeyRecord#apply(org.apache.james.jdkim.api.SignatureRecord)
	 */
	public static void apply(PublicKeyRecord pkr, SignatureRecord sign) {
		if (!pkr.getGranularityPattern().matcher(sign.getIdentityLocalPart()).matches()) {
			throw new IllegalStateException("inapplicable key identity local="+sign.getIdentityLocalPart()+" Pattern: "+pkr.getGranularityPattern().pattern());
		}
		
		if (!pkr.isHashMethodSupported(sign.getHashMethod())) {
			throw new IllegalStateException("inappropriate hash for a="+sign.getHashKeyType()+"/"+sign.getHashMethod());
		}
		if (!pkr.isKeyTypeSupported(sign.getHashKeyType())) {
			throw new IllegalStateException("inappropriate key type for a="+sign.getHashKeyType()+"/"+sign.getHashMethod());
		}
		
		if (pkr.isDenySubdomains()) {
			if (!sign.getIdentity().toString().toLowerCase().endsWith(("@"+sign.getDToken()).toLowerCase())) {
				throw new IllegalStateException("AUID in subdomain of SDID is not allowed by the public key record.");
			}
		}
		
	}

	/**
	 * Iterates through signature's declared lookup method
	 *
	 * @param sign the signature record
	 * @return an "applicable" PublicKeyRecord
	 * @throws TempFailException
	 * @throws PermFailException
	 */
	public PublicKeyRecord publicRecordLookup(SignatureRecord sign)
			throws TempFailException, PermFailException {
		// System.out.println(sign);
		PublicKeyRecord key = null;
		TempFailException lastTempFailure = null;
		PermFailException lastPermFailure = null;
		for(Iterator rlm = sign.getRecordLookupMethods().iterator(); key == null && rlm.hasNext(); ) {
			String method = (String) rlm.next();
			try {
				PublicKeyRecordRetriever pkrr = getPublicKeyRecordRetriever();
				List records = pkrr.getRecords(method, sign.getSelector().toString(), sign.getDToken().toString());
				PublicKeyRecord tempKey = publicKeySelector(records);
				// checks wether the key is applicable to the signature
				// TODO check with the IETF group to understand if this is the right thing to do.
				// TODO loggin
				apply(tempKey, sign);
				key = tempKey;
			} catch (IllegalStateException e) {
				lastPermFailure = new PermFailException("Inapplicable key: "+e.getMessage(), e);
			} catch (TempFailException tf) {
				lastTempFailure = tf;
			} catch (PermFailException pf) {
				lastPermFailure = pf;
			}
		}
		if (key == null) {
			if (lastTempFailure != null) throw lastTempFailure;
			else if (lastPermFailure != null) throw lastPermFailure;
			// this is unexpected because the publicKeySelector always returns null or exception
			else throw new PermFailException("no key for signature [unexpected condition]");
		}
		return key;
	}

	public void verify(InputStream is)
			throws IOException, FailException {
		Message message;
		try {
			message = new Message(is);
		} catch (MimeException e1) {
			throw new PermFailException("Mime parsing exception: "+e1.getMessage(), e1);
		}
		// System.out.println(message.getFields("DKIM-Signature"));
		List fields = message.getFields("DKIM-Signature");
		// if (fields.size() > 1) throw new RuntimeException("here we are!");
		if (fields.size() > 0) {
			// For each DKIM-signature we prepare an hashjob.
			// We calculate all hashes concurrently so to read
			// the inputstream only once.
			Map/* String, BodyHashJob */ bodyHashJobs = new HashMap();
			List/* OutputStream */ outputStreams = new LinkedList();
			Map/* String, Exception */ signatureExceptions = new Hashtable();
			for (Iterator i = fields.iterator(); i.hasNext(); ) {
				String fval = (String) i.next();
				try {
					int pos = fval.indexOf(':');
					if (pos > 0) {
						String v = fval.substring(pos + 1, fval.length());
						SignatureRecord sign;
						try {
							sign = newSignatureRecord(v);
							// validate
							sign.validate();
						} catch (IllegalStateException e) {
							throw new PermFailException(e.getMessage());
						}
			
						// TODO here we could check more parameters for validation
						// before running a network operation like the dns lookup.
						// e.g: the canonicalization method could be checked now.
						
						PublicKeyRecord key = publicRecordLookup(sign);
			
						List headers = sign.getHeaders();
			
						boolean verified = signatureVerify(message, fval,
								sign, key, headers);
						
						if (!verified) throw new PermFailException("Header signature does not verify");
			
						// we track all canonicalizations+limit+bodyHash we
						// see so to be able to check all of them in a single stream run.
						BodyHasher bhj = newBodyHasher(sign);
						
						bodyHashJobs.put(fval, bhj);
						outputStreams.add(bhj.getOutputStream());
			
					} else {
						throw new PermFailException("unexpected bad signature field");
					}
				} catch (TempFailException e) {
					signatureExceptions.put(fval, e);
				} catch (PermFailException e) {
					signatureExceptions.put(fval, e);
				} catch (InvalidKeyException e) {
					signatureExceptions.put(fval, new PermFailException(e.getMessage(), e));
				} catch (NoSuchAlgorithmException e) {
					signatureExceptions.put(fval, new PermFailException(e.getMessage(), e));
				} catch (SignatureException e) {
					signatureExceptions.put(fval, new PermFailException(e.getMessage(), e));
				}
			}
			
			OutputStream o;
			if (bodyHashJobs.size() == 0) {
				// TODO loops signatureExceptions to give a more complete response.
				if (signatureExceptions.size() == 1) {
					throw (FailException) signatureExceptions.values().iterator().next();
				} else {
					// System.out.println(signatureExceptions);
					throw new PermFailException("found "+signatureExceptions.size()+" invalid signatures");
				}
			} else if (bodyHashJobs.size() == 1) {
				o = (OutputStream) outputStreams.get(0);
			} else {
				o = new CompoundOutputStream(outputStreams);
			}

			// simultaneous computation of all the hashes.
			DKIMCommon.streamCopy(message.getBodyInputStream(), o);

			List/* BodyHashJob */ verifiedSignatures = new LinkedList();
			for (Iterator i = bodyHashJobs.keySet().iterator(); i.hasNext(); ) {
				String fval = (String) i.next();
				BodyHasher bhj = (BodyHasher) bodyHashJobs.get(fval);
	
				byte[] computedHash = bhj.getDigest();
				byte[] expectedBodyHash = bhj.getSignatureRecord().getBodyHash();
				
				if (!Arrays.equals(expectedBodyHash, computedHash)) {
					signatureExceptions.put(fval, new PermFailException("Computed bodyhash is different from the expected one"));
				} else {
					verifiedSignatures.add(bhj);
				}
			}
			
			if (verifiedSignatures.size() == 0) {
				if (signatureExceptions.size() == 1) {
					throw (FailException) signatureExceptions.values().iterator().next();
				} else {
					throw new PermFailException("found "+signatureExceptions.size()+" non verifying signatures");
				}
			} else {
				// TODO list good and bad signatures.
				for (Iterator i = signatureExceptions.keySet().iterator(); i.hasNext(); ) {
					String f = (String) i.next();
					System.out.println("DKIM-Error: "+((FailException) signatureExceptions.get(f)).getMessage()+" FIELD: "+f);
				}
				for (Iterator i = verifiedSignatures.iterator(); i.hasNext(); ) {
					BodyHasher bhj = (BodyHasher) i.next();
					System.out.println("DKIM-Pass: "+bhj.getSignatureRecord());
				}
			}
			
		} else {
			throw new PermFailException("DKIM-Signature field not found");
		}
	
		is.close();
	}

	private boolean signatureVerify(Headers h, String dkimSignature, SignatureRecord sign,
			PublicKeyRecord key, List headers)
			throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException {
		byte[] decoded = sign.getSignature();
	
		String signatureStub = dkimSignature.replaceAll("b=[^;]*", "b=");
	
		Signature signature = Signature.getInstance(sign.getHashMethod().toString().toUpperCase()+"with"+sign.getHashKeyType().toString().toUpperCase());
		signature.initVerify(key.getPublicKey());
	
		signatureCheck(h, sign, headers, signatureStub, signature);
		
		return signature.verify(decoded);
	}

}
