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
package org.apache.james.arc;
import org.apache.james.arc.exceptions.ArcException;
import org.apache.james.jdkim.api.BodyHasher;
import org.apache.james.jdkim.api.Headers;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.impl.BodyHasherImpl;
import org.apache.james.jdkim.impl.Message;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.List;
import java.util.Map;

/**
 * ARCSigner is responsible for generating and sealing ARC (Authenticated Received Chain)
 * signatures for email messages. It uses a provided private key and signature record template
 * to create ARC signature records, hash message bodies, and sign headers or message content.
 * <p>
 * Main responsibilities:
 * <ul>
 *   <li>Generate ARC signature records using a template</li>
 *   <li>Hash message bodies for signing</li>
 *   <li>Sign message headers and bodies using the provided private key</li>
 *   <li>Seal headers with ARC signatures</li>
 * </ul>
 * <p>
 * This class relies on the Java Cryptography Architecture and helper classes from the
 * org.apache.james.jdkim and org.apache.james.arc packages.
 */
public class ARCSigner {
    private final PrivateKey privateKey;
    private final String signatureRecordTemplate;

    public ARCSigner(String signatureRecordTemplate, PrivateKey privateKey) {
        this.privateKey = privateKey;
        this.signatureRecordTemplate = signatureRecordTemplate;
    }

    public SignatureRecord newSignatureRecordTemplate(String sigRecord) {
        return new ArcSignatureRecordImpl(sigRecord);
    }

    public BodyHasher newBodyHasher(SignatureRecord signRecord)
            throws PermFailException {
        return new BodyHasherImpl(signRecord);
    }

    public String generateAms(InputStream is){
        Message message;
        try (is) {
            message = getMessage(is);
            return getAmsHeader(message);
        } catch (IOException e) {
            throw new ArcException("IOException when working with email input stream", e);
        }
    }

    private String getAmsHeader(Message message) {
        try {
            SignatureRecord srt = newSignatureRecordTemplate(signatureRecordTemplate);
            BodyHasher bhj = newBodyHasher(srt);

            ARCCommon.streamCopy(message.getBodyInputStream(), bhj
                    .getOutputStream());

            return generateAms(message, bhj);
        } catch (PermFailException | IOException e) {
            throw new ArcException("Invalid signature record template", e);
        } finally {
            message.dispose();
        }
    }

    private static Message getMessage(InputStream is) {
        Message message;
        try {
            message = new Message(is);
        } catch (Exception e1) {
            throw new ArcException("MIME parsing exception: "
                    + e1.getMessage(), e1);
        }
        return message;
    }

    public String sealHeaders(Map<String, String> headersToSeal) {
        SignatureRecord srt = newSignatureRecordTemplate(signatureRecordTemplate);
        return seal(srt, headersToSeal);
    }

    public String generateAms(Headers message, BodyHasher bh) throws PermFailException {
        if (!(bh instanceof BodyHasherImpl)) {
            throw new PermFailException(
                    "Supplied BodyHasher has not been generated with this signer");
        }

        BodyHasherImpl bhj = (BodyHasherImpl) bh;
        List<CharSequence> headers;
        byte[] computedHash = bhj.getDigest();
        bhj.getSignatureRecord().setBodyHash(computedHash);
        headers = bhj.getSignatureRecord().getHeaders();

        try {
            byte[] signatureHash = signatureSign(message, bhj
                    .getSignatureRecord(), privateKey, headers);

            bhj.getSignatureRecord().setSignature(signatureHash);
            return "ARC-element:" + ((ArcSignatureRecordImpl)bhj.getSignatureRecord()).getStringInTemplateOrder();
        } catch (InvalidKeyException e) {
            throw new ArcException("Invalid key: " + e.getMessage(), e);
        } catch (NoSuchAlgorithmException e) {
            throw new ArcException("Unknown algorithm: " + e.getMessage(), e);
        } catch (SignatureException e) {
            throw new ArcException("Signing exception: " + e.getMessage(), e);
        }
    }

    public String seal(SignatureRecord signatureRecord, Map<String, String> headersToSeal) {

        try {
            byte[] signatureHash = signatureSeal(signatureRecord, privateKey, headersToSeal);

            signatureRecord.setSignature(signatureHash);
            return "ARC-element:" + ((ArcSignatureRecordImpl)signatureRecord).getStringInTemplateOrder();
        } catch (InvalidKeyException e) {
            throw new ArcException("Invalid key: " + e.getMessage(), e);
        } catch (NoSuchAlgorithmException e) {
            throw new ArcException("Unknown algorithm: " + e.getMessage(), e);
        } catch (SignatureException e) {
            throw new ArcException("Signing exception: " + e.getMessage(), e);
        } catch (PermFailException e) {
            throw new ArcException("PermFail exception received " + e.getMessage(), e);
        }
    }

    private byte[] signatureSeal(SignatureRecord sign, PrivateKey key, Map<String, String> headersToSeal)
            throws NoSuchAlgorithmException, InvalidKeyException,
            SignatureException, PermFailException {
        Signature signature = Signature.getInstance(sign.getHashMethod()
                .toString().toUpperCase()
                + "with" + sign.getHashKeyType().toString().toUpperCase());
        signature.initSign(key);

        ARCCommon.arcSeal(sign, headersToSeal, signature);
        return signature.sign();

    }

    private byte[] signatureSign(Headers h, SignatureRecord sign,
                                 PrivateKey key, List<CharSequence> headers)
            throws NoSuchAlgorithmException, InvalidKeyException,
            SignatureException, PermFailException {

        Signature signature = Signature.getInstance(sign.getHashMethod()
                .toString().toUpperCase()
                + "with" + sign.getHashKeyType().toString().toUpperCase());
        signature.initSign(key);

        ARCCommon.amsSign(h, sign, headers, signature);
        return signature.sign();
    }
}

