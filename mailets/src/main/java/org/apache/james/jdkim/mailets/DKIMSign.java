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

package org.apache.james.jdkim.mailets;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.mail.Header;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import org.apache.james.jdkim.DKIMSigner;
import org.apache.james.jdkim.api.BodyHasher;
import org.apache.james.jdkim.api.Headers;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.mailet.Mail;
import org.apache.mailet.base.GenericMailet;

/**
 * This mailet sign a message using the DKIM protocol
 * 
 * Sample configuration:
 * <pre><code>
 * &lt;mailet match="All" class="DKIMSign"&gt;
 *   &lt;signatureTemplate&gt;v=1; s=selector; d=example.com; h=from:to:received:received; a=rsa-sha256; bh=; b=;&lt;/signatureTemplate&gt;
 *   &lt;privateKey&gt;MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBANgNpgpfPBVjCpZsuGa4nrppMA3zCYNH6t8cTwd+eRI5rHSgihMznOq5mtMujfTzvRgx9jPHB8HqP83PdB3CtQP+3RgxgmJQrJYmcIp9lcckEn7J9Eevuhb5RbdxWj0IbZsF8jGwifBh7XvmD1SPKe0mla56p0QijVzZuG/0ynrpAgMBAAECgYEAjxdzCdmLRKrk3z3AX6AU2GdEQWjeuwkNoJjyKod0DkMOWevdptv/KGKnDQj/UeWALp8gbah7Fc5cVaX5RKCpG3WRO32NeFUUTGDyY2SjZR6UDAW2yXwJGNVxhA5x514f9Yz+ZeODbBSqpl6cGaUqUPq81vvSMUl5VoMn/ufuPwECQQD02QfYPhmCP8g4BVhxxlgfvj5WA7R7tWRSNCT3C0naPpwaono9+PSuhUgxRbOgFvxh8StHyXomdVBt/LzeAl6JAkEA4eTejDsmMCfxe47JnHbgpxNphYpSQBB9FZgMUU5hAXgpX3EtIS3JxjSSOx3EYoO51ZywBOWUXNcMJAXoNM0hYQJAQDnZ4/BOMqtWctN8IsQbg6Acq+Vm53hqa2HAPIlagwQfYKE0HaN7U3gkusAE4T6GT466gqcoAoSNZ3x/cmD+uQJAePyZCaiAephaKSA/8VJmXnXyNXjxNqjeJduq9T0yjZPrLNg0IKoigMsVax41WcJNnRBv4h+IR/VR5lVXmjgn4QJANq02dLdX2phQqOP+Ss1EP9TT7t6HxLbKUuoPdGVKf0q1gZEyAC1Re2I4SLMEfpt3+ivMj1X2zDzIHP5mogfblA==&lt;/privateKey&gt;
 * &lt;/mailet&gt;
 * </code></pre>
 *
 * @version CVS $Revision: 713949 $ $Date: 2008-11-14 08:40:21 +0100 (ven, 14 nov 2008) $
 * @since 2.2.0
 */
public class DKIMSign extends GenericMailet {

	/**
	 * An adapter to let DKIMSigner read headers from MimeMessage
	 */
	private final class MimeMessageHeaders implements Headers {

		private Map/* String, String */ headers;
		private List/* String */ fields;

		public MimeMessageHeaders(MimeMessage message) throws MessagingException {
			headers = new HashMap();
			fields = new LinkedList();
			for (Enumeration e = message.getAllHeaderLines(); e.hasMoreElements(); ) {
				String head = (String) e.nextElement();
				int p = head.indexOf(':');
				if (p <= 0) throw new MessagingException("Bad header line: "+head);
				String headerName = head.substring(0, p).trim();
				String headerNameLC = headerName.toLowerCase();
				fields.add(headerName);
				List/* String */ strings = (List) headers.get(headerNameLC);
				if (strings == null) {
					strings = new LinkedList();
					headers.put(headerNameLC, strings);
				}
				strings.add(head);
			}
		}

		public List getFields() {
			return fields;
		}

		public List getFields(String name) {
			return (List) headers.get(name);
		}
	}

	private String signatureTemplate;
	private PrivateKey privateKey;

	public void init() throws MessagingException {
		signatureTemplate = getInitParameter("signatureTemplate");
		String privateKeyString = getInitParameter("privateKey");
	    try {
			privateKey = DKIMSigner.getPrivateKey(privateKeyString);
		} catch (NoSuchAlgorithmException e) {
			throw new MessagingException("Unknown private key algorythm: "+e.getMessage(), e);
		} catch (InvalidKeySpecException e) {
			throw new MessagingException("PrivateKey should be in base64 encoded PKCS8 (der) format: "+e.getMessage(), e);
		}
	}

	public void service(Mail mail) throws MessagingException {
		DKIMSigner signer = new DKIMSigner(signatureTemplate, privateKey);
		SignatureRecord signRecord = signer.newSignatureRecord(signatureTemplate);
		try {
			BodyHasher bhj = signer.newBodyHasher(signRecord);
			MimeMessage message = mail.getMessage();
			Headers headers = new MimeMessageHeaders(message);
			try {
				message.writeTo(new HeaderSkippingOutputStream(bhj.getOutputStream()));
				bhj.getOutputStream().close();
			} catch (IOException e) {
				throw new MessagingException("Exception calculating bodyhash: "+e.getMessage(), e);
			}
			String signatureHeader = signer.sign(headers, bhj);
			// Unfortunately JavaMail does not give us a method to add headers on top.
			// message.addHeaderLine(signatureHeader);
			prependHeader(message, signatureHeader);
		} catch (NoSuchAlgorithmException e) {
			throw new MessagingException("Unknown algorythm: "+e.getMessage(), e);
		} catch (PermFailException e) {
			throw new MessagingException("PermFail while signing: "+e.getMessage(), e);
		}

	}

	private void prependHeader(MimeMessage message, String signatureHeader)
			throws MessagingException {
		List prevHeader = new LinkedList();
		// read all the headers
		for (Enumeration e = message.getAllHeaderLines(); e.hasMoreElements(); ) { 
			String headerLine = (String) e.nextElement();
			prevHeader.add(headerLine);
		}
		// remove all the headers
		for (Enumeration e = message.getAllHeaders(); e.hasMoreElements(); ) {
			Header header = (Header) e.nextElement();
			message.removeHeader(header.getName());
		}
		// add our header
		message.addHeaderLine(signatureHeader);
		// add the remaining headers using "addHeaderLine" that won't alter the insertion order.
		for (Iterator i = prevHeader.iterator(); i.hasNext(); ) {
			String header = (String) i.next();
			message.addHeaderLine(header);
		}
	}

}
