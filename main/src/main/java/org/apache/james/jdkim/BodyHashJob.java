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

import java.io.OutputStream;

import org.apache.james.jdkim.canon.DigestOutputStream;

public class BodyHashJob {

	private SignatureRecord sign;
	private DigestOutputStream digesterOS;
	private OutputStream out;
	private String field;

	public OutputStream getOutputStream() {
		return out;
	}

	public SignatureRecord getSignatureRecord() {
		return sign;
	}

	public DigestOutputStream getDigesterOutputStream() {
		return digesterOS;
	}

	public void setSignatureRecord(SignatureRecord sign) {
		this.sign = sign;
	}

	public void setDigestOutputStream(DigestOutputStream dout) {
		this.digesterOS = dout;
	}

	public void setOutputStream(OutputStream out) {
		this.out = out;
	}

	public void setField(String f) {
		this.field = f;
	}
	
	public String getField() {
		return this.field;
	}

}
