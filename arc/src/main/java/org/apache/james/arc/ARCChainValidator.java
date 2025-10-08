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
import org.apache.james.mime4j.dom.Message;
import org.apache.james.mime4j.dom.Header;
import org.apache.james.mime4j.stream.Field;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Validates the ARC (Authenticated Received Chain) chain in an email message.
 * <p>
 * This class provides methods to validate the ARC chain by checking the structure,
 * verifying ARC-Message-Signature and ARC-Seal headers, and ensuring the integrity
 * of previous ARC hops. It uses DNS records and cryptographic verification to
 * ensure the authenticity of the ARC chain.
 * </p>
 */
public class ARCChainValidator {
    public static final String ARC_MESSAGE_SIGNATURE = "ARC-Message-Signature";
    public static final String ARC_SEAL = "ARC-Seal";
    private static final String SHA256_RSA = "SHA256withRSA";
    private final Pattern INST_RGX_PATTERN = Pattern.compile("i=([0-9]+)");
    private final PublicKeyRetrieverArc _keyRecordRetriever;

    public ARCChainValidator(PublicKeyRetrieverArc keyRecordRetriever) {
        this._keyRecordRetriever = keyRecordRetriever;
    }

    public String validateArcChain(Message message) {

        Header messageHeaders = message.getHeader();
        int curInstance = getCurrentInstance(messageHeaders);  // Incremented by 1

        if (curInstance == 1) { //we are the first ARC Hop and there is no previous ARC hops in the chain to validate
            return "none";
        }
        else if (curInstance > 51) { // Not allowed to be > 50
            return "fail";
        }
        else { // there are previous ARC hops that need to be validated
            return validatePreviousArcHops(message, messageHeaders, curInstance);
        }
    }

    private String validatePreviousArcHops(Message message, Header messageHeaders, int myInstance) {
        ARCVerifier arcVerifier = new ARCVerifier(_keyRecordRetriever);
        Map<Integer, List<Field>> arcHeadersByI = arcVerifier.getArcHeadersByI(messageHeaders.getFields());
        int numArcInstances = myInstance -1;
        boolean isArcSetStructureOK = arcVerifier.validateArcSetStructure(arcHeadersByI);
        if (!isArcSetStructureOK) {
            return "fail";
        }

        Set<Field> prevArcSet;
        prevArcSet = arcVerifier.extractArcSet(messageHeaders, numArcInstances);
        if  (prevArcSet != null) {
            boolean amsOk = checkArcAms(prevArcSet, message, arcVerifier);
            boolean asOk = checkArcSeal(messageHeaders.getFields(), numArcInstances, arcVerifier);
            if (amsOk && asOk) {
                return "pass";
            }
        }
        return  "fail";
    }

    private boolean checkArcAms(Set<Field> prevArcSet, Message message, ARCVerifier arcVerifier){
        boolean retVal = false;

        Field amsHeader = prevArcSet.stream()
                .filter(f -> f.getName().equalsIgnoreCase(ARC_MESSAGE_SIGNATURE))
                .findFirst().orElse(null);
        if (amsHeader == null) return retVal;

        String txtDnsRecord = arcVerifier.getTxtDnsRecordByField(amsHeader);
        if (txtDnsRecord == null) return retVal;

        retVal = arcVerifier.verifyAms(amsHeader, message, txtDnsRecord);

        return retVal;
    }

    private boolean checkArcSeal(List<Field> headers, int instToVerify, ARCVerifier arcVerifier) {
        boolean retVal = false;
        Map<Integer, List<Field>> arcHeadersByI = arcVerifier.getArcHeadersByI(headers);
        ArcSealVerifyData verifyData = arcVerifier.buildArcSealSigningData(arcHeadersByI, instToVerify);
        Field arcSealHeader = headers.stream()
                .filter(f -> f.getName().equalsIgnoreCase(ARC_SEAL))
                .findFirst().orElse(null);
        if (arcSealHeader == null) return retVal;

        String txtDnsRecord = arcVerifier.getTxtDnsRecordByField(arcSealHeader);
        if (txtDnsRecord == null) return retVal;

        PublicKey publicKey = arcVerifier.parsePublicKeyFromDns(txtDnsRecord);
        if (publicKey == null) {
            throw new ArcException(String.format("Unable to parse public key from dns record %s", txtDnsRecord));
        }

        String b64 = verifyData.getB64Signature();
        String data = verifyData.getSignedData();

        try {
            Signature sig = Signature.getInstance(SHA256_RSA);
            sig.initVerify(publicKey);
            sig.update(data.getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = Base64.getDecoder().decode(b64);
            retVal = sig.verify(signatureBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new ArcException("Unsupported signing algorithm", e);
        }
        catch (InvalidKeyException e) {
            throw new ArcException(String.format("Invalid public key used for %s record", txtDnsRecord), e);
        } catch (SignatureException e) {
            throw new ArcException(String.format("Invalid signature for %s record", txtDnsRecord), e);
        }
        return retVal;
    }

    public int getCurrentInstance(Header messageHeaders) {
        int retVal = 1;
        for (Field field : messageHeaders.getFields()) {
            if (field.getName().startsWith("ARC-")) {
                Matcher m = INST_RGX_PATTERN.matcher(field.getBody());
                if (m.find()) {
                    int iVal = Integer.parseInt(m.group(1));
                    if (iVal >= retVal) {
                        retVal = iVal + 1;
                    }
                }
            }
        }
        return retVal;
    }
}
