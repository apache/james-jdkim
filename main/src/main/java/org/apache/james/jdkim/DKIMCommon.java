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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.james.jdkim.canon.DebugOutputStream;
import org.apache.james.jdkim.canon.DigestOutputStream;
import org.apache.james.jdkim.canon.LimitedOutputStream;
import org.apache.james.jdkim.canon.RelaxedBodyCanonicalizer;
import org.apache.james.jdkim.canon.SimpleBodyCanonicalizer;
import org.apache.james.jdkim.tagvalue.SignatureRecordImpl;

public class DKIMCommon {

	private static final boolean DEEP_DEBUG = false;

	public static void updateSignature(Signature signature, boolean relaxed,
			CharSequence header, String fv) throws SignatureException {
		if (relaxed) {
			if (DEEP_DEBUG)
				System.out
						.println("#" + header.toString().toLowerCase() + ":-");
			signature.update(header.toString().toLowerCase().getBytes());
			signature.update(":".getBytes());
			String headerValue = fv.substring(fv.indexOf(':') + 1);
			headerValue = headerValue.replaceAll("\r\n[\t ]", " ");
			headerValue = headerValue.replaceAll("[\t ]+", " ");
			headerValue = headerValue.trim();
			signature.update(headerValue.getBytes());
			if (DEEP_DEBUG)
				System.out.println("#" + headerValue + "#");
		} else {
			signature.update(fv.getBytes());
			if (DEEP_DEBUG)
				System.out.println("#" + fv + "#");
		}
	}

	protected static void signatureCheck(Headers h, SignatureRecord sign,
			List headers, String signatureStub, Signature signature)
			throws SignatureException {
		// TODO make this check better (parse the c field inside sign)
		boolean relaxedHeaders = "relaxed".equals(sign
				.getHeaderCanonicalisationMethod());

		// NOTE: this could be improved by using iterators.
		// NOTE: also this rely on the list returned by Message being in
		// insertion order
		Map/* String, Integer */processedHeader = new HashMap();

		for (Iterator i = headers.iterator(); i.hasNext();) {
			CharSequence header = (CharSequence) i.next();
			// TODO check this getter is case insensitive
			List hl = h.getFields(header.toString());
			if (hl != null && hl.size() > 0) {
				Integer done = (Integer) processedHeader.get(header.toString());
				if (done == null)
					done = new Integer(0); /* Integer.valueOf(0) */
				int doneHeaders = done.intValue() + 1;
				if (doneHeaders <= hl.size()) {
					String fv = (String) hl.get(hl.size() - doneHeaders);
					updateSignature(signature, relaxedHeaders, header, fv);
					signature.update("\r\n".getBytes());
					processedHeader.put(header.toString(), new Integer(
							doneHeaders));
				}
			}
		}

		updateSignature(signature, relaxedHeaders, "dkim-signature",
				signatureStub);
	}

	public SignatureRecord newSignatureRecord(String record) {
		return new SignatureRecordImpl(record);
	}

	static OutputStream prepareCanonicalizerOutputStream(int limit,
			boolean relaxedBody, OutputStream dout) {
		OutputStream out = dout;
		if (limit != -1)
			out = new LimitedOutputStream(out, limit);
		if (relaxedBody)
			out = new RelaxedBodyCanonicalizer(out);
		else
			out = new SimpleBodyCanonicalizer(out);
		return out;
	}

	public static void streamCopy(InputStream bodyIs, OutputStream out)
			throws IOException {
		byte[] buffer = new byte[2048];
		int read;
		while ((read = bodyIs.read(buffer)) > 0) {
			out.write(buffer, 0, read);
		}
		bodyIs.close();
		out.close();
	}

	public static BodyHashJob prepareBodyHashJob(SignatureRecord sign,
			String f) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance(sign.getHashAlgo().toString());
		
		BodyHashJob bhj = new BodyHashJob();

		int limit = sign.getBodyHashLimit();

		// TODO enhance this to use a lookup service.
		boolean relaxedBody = "relaxed".equals(sign
				.getBodyCanonicalisationMethod());

		DigestOutputStream dout = new DigestOutputStream(md);
		
		OutputStream out = dout;
		if (DEEP_DEBUG) out = new DebugOutputStream(out);
		out = DKIMCommon.prepareCanonicalizerOutputStream(limit,
				relaxedBody, out);

		bhj.setSignatureRecord(sign);
		bhj.setDigestOutputStream(dout);
		bhj.setOutputStream(out);
		bhj.setField(f);
		return bhj;
	}

	public DKIMCommon() {
		super();
	}

}