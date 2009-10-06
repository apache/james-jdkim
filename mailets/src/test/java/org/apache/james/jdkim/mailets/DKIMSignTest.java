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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Properties;

import javax.mail.Address;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMessage.RecipientType;

import junit.framework.TestCase;

import org.apache.james.jdkim.DKIMVerifier;
import org.apache.james.jdkim.FailException;
import org.apache.james.jdkim.MockPublicKeyRecordRetriever;
import org.apache.james.jdkim.PermFailException;
import org.apache.mailet.Mail;
import org.apache.mailet.Mailet;
import org.apache.mailet.base.test.MockMail;
import org.apache.mailet.base.test.MockMailContext;
import org.apache.mailet.base.test.MockMailetConfig;

public class DKIMSignTest extends TestCase {
	
	public void testDKIMSign() throws MessagingException, IOException, FailException {
	    String message ="Received: by 10.XX.XX.12 with SMTP id dfgskldjfhgkljsdfhgkljdhfg;\r\n\tTue, 06 Oct 2009 07:37:34 -0700 (PDT)\r\nReturn-Path: <bounce@example.com>\r\nReceived: from example.co.uk (example.co.uk [XX.XXX.125.19])\r\n\tby mx.example.com with ESMTP id dgdfgsdfgsd.97.2009.10.06.07.37.32;\r\n\tTue, 06 Oct 2009 07:37:32 -0700 (PDT)\r\nFrom: apache@bago.org\r\nTo: apache@bago.org\r\n\r\nbody\r\n";
		
	    Mailet mailet = new DKIMSign();
	
	    MockMailetConfig mci = new MockMailetConfig("Test",new MockMailContext());
	    mci.setProperty("signatureTemplate","v=1; s=selector; d=example.com; h=from:to:received:received; a=rsa-sha256; bh=; b=;");
	    mci.setProperty("privateKey","MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBANgNpgpfPBVjCpZsuGa4nrppMA3zCYNH6t8cTwd+eRI5rHSgihMznOq5mtMujfTzvRgx9jPHB8HqP83PdB3CtQP+3RgxgmJQrJYmcIp9lcckEn7J9Eevuhb5RbdxWj0IbZsF8jGwifBh7XvmD1SPKe0mla56p0QijVzZuG/0ynrpAgMBAAECgYEAjxdzCdmLRKrk3z3AX6AU2GdEQWjeuwkNoJjyKod0DkMOWevdptv/KGKnDQj/UeWALp8gbah7Fc5cVaX5RKCpG3WRO32NeFUUTGDyY2SjZR6UDAW2yXwJGNVxhA5x514f9Yz+ZeODbBSqpl6cGaUqUPq81vvSMUl5VoMn/ufuPwECQQD02QfYPhmCP8g4BVhxxlgfvj5WA7R7tWRSNCT3C0naPpwaono9+PSuhUgxRbOgFvxh8StHyXomdVBt/LzeAl6JAkEA4eTejDsmMCfxe47JnHbgpxNphYpSQBB9FZgMUU5hAXgpX3EtIS3JxjSSOx3EYoO51ZywBOWUXNcMJAXoNM0hYQJAQDnZ4/BOMqtWctN8IsQbg6Acq+Vm53hqa2HAPIlagwQfYKE0HaN7U3gkusAE4T6GT466gqcoAoSNZ3x/cmD+uQJAePyZCaiAephaKSA/8VJmXnXyNXjxNqjeJduq9T0yjZPrLNg0IKoigMsVax41WcJNnRBv4h+IR/VR5lVXmjgn4QJANq02dLdX2phQqOP+Ss1EP9TT7t6HxLbKUuoPdGVKf0q1gZEyAC1Re2I4SLMEfpt3+ivMj1X2zDzIHP5mogfblA==");
	
	    mailet.init(mci);
	
	    Mail mail = new MockMail();
	    mail.setMessage(new MimeMessage(Session
	            .getDefaultInstance(new Properties()),
	            new ByteArrayInputStream(message.getBytes())));
	
	    mailet.service(mail);

	    Mailet m7bit = new ConvertTo7Bit();
	    m7bit.init(mci);
	    m7bit.service(mail);

	    ByteArrayOutputStream rawMessage = new ByteArrayOutputStream();
	    mail.getMessage().writeTo(rawMessage);
	    String res = rawMessage.toString();
	    
		MockPublicKeyRecordRetriever mockPublicKeyRecordRetriever = new MockPublicKeyRecordRetriever("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDYDaYKXzwVYwqWbLhmuJ66aTAN8wmDR+rfHE8HfnkSOax0oIoTM5zquZrTLo30870YMfYzxwfB6j/Nz3QdwrUD/t0YMYJiUKyWJnCKfZXHJBJ+yfRHr7oW+UW3cVo9CG2bBfIxsInwYe175g9UjyntJpWueqdEIo1c2bhv9Mp66QIDAQAB;", "selector", "example.com");
	    new DKIMVerifier(mockPublicKeyRecordRetriever).verify(new ByteArrayInputStream(res.getBytes()));
	}
	
	public void testDKIMSignMessageAsText() throws MessagingException, IOException, FailException {
	    MimeMessage mm = new MimeMessage(Session.getDefaultInstance(new Properties()));
	    mm.addFrom(new Address[] { new InternetAddress("io@bago.org") });
	    mm.addRecipient(RecipientType.TO, new InternetAddress("io@bago.org"));
	    mm.setText("An 8bit encoded body with �uro symbol.", "ISO-8859-15");
	    
	    Mailet mailet = new DKIMSign();
	
	    MockMailetConfig mci = new MockMailetConfig("Test",new MockMailContext());
	    mci.setProperty("signatureTemplate","v=1; s=selector; d=example.com; h=from:to:received:received; a=rsa-sha256; bh=; b=;");
	    mci.setProperty("privateKey","MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBANgNpgpfPBVjCpZsuGa4nrppMA3zCYNH6t8cTwd+eRI5rHSgihMznOq5mtMujfTzvRgx9jPHB8HqP83PdB3CtQP+3RgxgmJQrJYmcIp9lcckEn7J9Eevuhb5RbdxWj0IbZsF8jGwifBh7XvmD1SPKe0mla56p0QijVzZuG/0ynrpAgMBAAECgYEAjxdzCdmLRKrk3z3AX6AU2GdEQWjeuwkNoJjyKod0DkMOWevdptv/KGKnDQj/UeWALp8gbah7Fc5cVaX5RKCpG3WRO32NeFUUTGDyY2SjZR6UDAW2yXwJGNVxhA5x514f9Yz+ZeODbBSqpl6cGaUqUPq81vvSMUl5VoMn/ufuPwECQQD02QfYPhmCP8g4BVhxxlgfvj5WA7R7tWRSNCT3C0naPpwaono9+PSuhUgxRbOgFvxh8StHyXomdVBt/LzeAl6JAkEA4eTejDsmMCfxe47JnHbgpxNphYpSQBB9FZgMUU5hAXgpX3EtIS3JxjSSOx3EYoO51ZywBOWUXNcMJAXoNM0hYQJAQDnZ4/BOMqtWctN8IsQbg6Acq+Vm53hqa2HAPIlagwQfYKE0HaN7U3gkusAE4T6GT466gqcoAoSNZ3x/cmD+uQJAePyZCaiAephaKSA/8VJmXnXyNXjxNqjeJduq9T0yjZPrLNg0IKoigMsVax41WcJNnRBv4h+IR/VR5lVXmjgn4QJANq02dLdX2phQqOP+Ss1EP9TT7t6HxLbKUuoPdGVKf0q1gZEyAC1Re2I4SLMEfpt3+ivMj1X2zDzIHP5mogfblA==");
	
	    mailet.init(mci);
	
	    Mail mail = new MockMail();
	    mail.setMessage(mm);

	    Mailet m7bit = new ConvertTo7Bit();
	    m7bit.init(mci);

	    mailet.service(mail);

	    m7bit.service(mail);

	    ByteArrayOutputStream rawMessage = new ByteArrayOutputStream();
	    mail.getMessage().writeTo(rawMessage);
	    String res = rawMessage.toString();
	    
		MockPublicKeyRecordRetriever mockPublicKeyRecordRetriever = new MockPublicKeyRecordRetriever("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDYDaYKXzwVYwqWbLhmuJ66aTAN8wmDR+rfHE8HfnkSOax0oIoTM5zquZrTLo30870YMfYzxwfB6j/Nz3QdwrUD/t0YMYJiUKyWJnCKfZXHJBJ+yfRHr7oW+UW3cVo9CG2bBfIxsInwYe175g9UjyntJpWueqdEIo1c2bhv9Mp66QIDAQAB;", "selector", "example.com");
	    new DKIMVerifier(mockPublicKeyRecordRetriever).verify(new ByteArrayInputStream(res.getBytes()));
	}

	public void testDKIMSignMessageAsObjectConvertedTo7Bit() throws MessagingException, IOException, FailException {
	    MimeMessage mm = new MimeMessage(Session.getDefaultInstance(new Properties()));
	    mm.addFrom(new Address[] { new InternetAddress("io@bago.org") });
	    mm.addRecipient(RecipientType.TO, new InternetAddress("io@bago.org"));
	    mm.setContent("An 8bit encoded body with \u20ACuro symbol.", "text/plain; charset=iso-8859-15");
	    mm.setHeader("Content-Transfer-Encoding", "8bit");
	    mm.saveChanges();
	
	    MockMailContext mockMailContext = new MockMailContext();
	    mockMailContext.getServerInfo();
		MockMailetConfig mci = new MockMailetConfig("Test",mockMailContext);
	    mci.setProperty("signatureTemplate","v=1; s=selector; d=example.com; h=from:to:received:received; a=rsa-sha256; bh=; b=;");
	    mci.setProperty("privateKey","MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBANgNpgpfPBVjCpZsuGa4nrppMA3zCYNH6t8cTwd+eRI5rHSgihMznOq5mtMujfTzvRgx9jPHB8HqP83PdB3CtQP+3RgxgmJQrJYmcIp9lcckEn7J9Eevuhb5RbdxWj0IbZsF8jGwifBh7XvmD1SPKe0mla56p0QijVzZuG/0ynrpAgMBAAECgYEAjxdzCdmLRKrk3z3AX6AU2GdEQWjeuwkNoJjyKod0DkMOWevdptv/KGKnDQj/UeWALp8gbah7Fc5cVaX5RKCpG3WRO32NeFUUTGDyY2SjZR6UDAW2yXwJGNVxhA5x514f9Yz+ZeODbBSqpl6cGaUqUPq81vvSMUl5VoMn/ufuPwECQQD02QfYPhmCP8g4BVhxxlgfvj5WA7R7tWRSNCT3C0naPpwaono9+PSuhUgxRbOgFvxh8StHyXomdVBt/LzeAl6JAkEA4eTejDsmMCfxe47JnHbgpxNphYpSQBB9FZgMUU5hAXgpX3EtIS3JxjSSOx3EYoO51ZywBOWUXNcMJAXoNM0hYQJAQDnZ4/BOMqtWctN8IsQbg6Acq+Vm53hqa2HAPIlagwQfYKE0HaN7U3gkusAE4T6GT466gqcoAoSNZ3x/cmD+uQJAePyZCaiAephaKSA/8VJmXnXyNXjxNqjeJduq9T0yjZPrLNg0IKoigMsVax41WcJNnRBv4h+IR/VR5lVXmjgn4QJANq02dLdX2phQqOP+Ss1EP9TT7t6HxLbKUuoPdGVKf0q1gZEyAC1Re2I4SLMEfpt3+ivMj1X2zDzIHP5mogfblA==");
	
	
	    Mail mail = new MockMail();
	    mail.setMessage(mm);
	    
	    Mailet mailet = new DKIMSign();
	    mailet.init(mci);
	    
	    Mailet m7bit = new ConvertTo7Bit();
	    m7bit.init(mci);
	    m7bit.service(mail);
	    
	    mailet.service(mail);
	
	    m7bit.service(mail);

	    ByteArrayOutputStream rawMessage = new ByteArrayOutputStream();
	    mail.getMessage().writeTo(rawMessage);
	    String res = rawMessage.toString();
	    
		MockPublicKeyRecordRetriever mockPublicKeyRecordRetriever = new MockPublicKeyRecordRetriever("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDYDaYKXzwVYwqWbLhmuJ66aTAN8wmDR+rfHE8HfnkSOax0oIoTM5zquZrTLo30870YMfYzxwfB6j/Nz3QdwrUD/t0YMYJiUKyWJnCKfZXHJBJ+yfRHr7oW+UW3cVo9CG2bBfIxsInwYe175g9UjyntJpWueqdEIo1c2bhv9Mp66QIDAQAB;", "selector", "example.com");
	    new DKIMVerifier(mockPublicKeyRecordRetriever).verify(new ByteArrayInputStream(res.getBytes()));
	}

	public void testDKIMSignMessageAsObjectNotConverted() throws MessagingException, IOException, FailException {
	    MimeMessage mm = new MimeMessage(Session.getDefaultInstance(new Properties()));
	    mm.addFrom(new Address[] { new InternetAddress("io@bago.org") });
	    mm.addRecipient(RecipientType.TO, new InternetAddress("io@bago.org"));
	    mm.setContent("An 8bit encoded body with \u20ACuro symbol.", "text/plain; charset=iso-8859-15");
	    mm.setHeader("Content-Transfer-Encoding", "8bit");
	    mm.saveChanges();
	
	    MockMailContext mockMailContext = new MockMailContext();
	    mockMailContext.getServerInfo();
		MockMailetConfig mci = new MockMailetConfig("Test",mockMailContext);
	    mci.setProperty("signatureTemplate","v=1; s=selector; d=example.com; h=from:to:received:received; a=rsa-sha256; bh=; b=;");
	    mci.setProperty("privateKey","MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBANgNpgpfPBVjCpZsuGa4nrppMA3zCYNH6t8cTwd+eRI5rHSgihMznOq5mtMujfTzvRgx9jPHB8HqP83PdB3CtQP+3RgxgmJQrJYmcIp9lcckEn7J9Eevuhb5RbdxWj0IbZsF8jGwifBh7XvmD1SPKe0mla56p0QijVzZuG/0ynrpAgMBAAECgYEAjxdzCdmLRKrk3z3AX6AU2GdEQWjeuwkNoJjyKod0DkMOWevdptv/KGKnDQj/UeWALp8gbah7Fc5cVaX5RKCpG3WRO32NeFUUTGDyY2SjZR6UDAW2yXwJGNVxhA5x514f9Yz+ZeODbBSqpl6cGaUqUPq81vvSMUl5VoMn/ufuPwECQQD02QfYPhmCP8g4BVhxxlgfvj5WA7R7tWRSNCT3C0naPpwaono9+PSuhUgxRbOgFvxh8StHyXomdVBt/LzeAl6JAkEA4eTejDsmMCfxe47JnHbgpxNphYpSQBB9FZgMUU5hAXgpX3EtIS3JxjSSOx3EYoO51ZywBOWUXNcMJAXoNM0hYQJAQDnZ4/BOMqtWctN8IsQbg6Acq+Vm53hqa2HAPIlagwQfYKE0HaN7U3gkusAE4T6GT466gqcoAoSNZ3x/cmD+uQJAePyZCaiAephaKSA/8VJmXnXyNXjxNqjeJduq9T0yjZPrLNg0IKoigMsVax41WcJNnRBv4h+IR/VR5lVXmjgn4QJANq02dLdX2phQqOP+Ss1EP9TT7t6HxLbKUuoPdGVKf0q1gZEyAC1Re2I4SLMEfpt3+ivMj1X2zDzIHP5mogfblA==");
	
	
	    Mail mail = new MockMail();
	    mail.setMessage(mm);
	    
	    Mailet mailet = new DKIMSign();
	    mailet.init(mci);
	    
	    Mailet m7bit = new ConvertTo7Bit();
	    m7bit.init(mci);
	    // m7bit.service(mail);
	    
	    mailet.service(mail);
	
	    m7bit.service(mail);

	    ByteArrayOutputStream rawMessage = new ByteArrayOutputStream();
	    mail.getMessage().writeTo(rawMessage);
	    String res = rawMessage.toString();
	    
		MockPublicKeyRecordRetriever mockPublicKeyRecordRetriever = new MockPublicKeyRecordRetriever("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDYDaYKXzwVYwqWbLhmuJ66aTAN8wmDR+rfHE8HfnkSOax0oIoTM5zquZrTLo30870YMfYzxwfB6j/Nz3QdwrUD/t0YMYJiUKyWJnCKfZXHJBJ+yfRHr7oW+UW3cVo9CG2bBfIxsInwYe175g9UjyntJpWueqdEIo1c2bhv9Mp66QIDAQAB;", "selector", "example.com");
	    try {
	    	new DKIMVerifier(mockPublicKeyRecordRetriever).verify(new ByteArrayInputStream(res.getBytes()));
	    	fail("Expected PermFail");
	    } catch (PermFailException e) {
	    	
	    }
	}

}
