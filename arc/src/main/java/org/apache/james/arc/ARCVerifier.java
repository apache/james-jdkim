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
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.exceptions.TempFailException;
import org.apache.james.mime4j.dom.Header;
import org.apache.james.mime4j.dom.Message;
import org.apache.james.mime4j.stream.Field;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility class for verifying ARC (Authenticated Received Chain) headers in email messages.
 * <p>
 * Provides methods for:
 * <ul>
 *   <li>Verifying ARC-Message-Signature (AMS) using public keys from DNS</li>
 *   <li>Parsing and canonicalizing ARC headers and bodies</li>
 *   <li>Validating ARC set structure and continuity</li>
 *   <li>Building DNS queries for public key retrieval</li>
 *   <li>Extracting and organizing ARC headers by instance</li>
 *   <li>Looking up DNS TXT records for ARC public keys</li>
 *   <li>Building signing data for ARC-Seal verification</li>
 * </ul>
 * <p>
 * This class is not instantiable and all methods are static.
 */
public class ARCVerifier {
    public static final String RSA = "RSA";
    public static final String B_TAG_REGEX = "b=[^;]*";
    public static final Pattern TAG_PATTERN = Pattern.compile("([a-z]+)=([^;]+)");
    public static final Pattern PUBLIC_KEY_PATTERN = Pattern.compile("p=([^;]+)");
    public static final String ARC_AUTHENTICATION_RESULTS = "ARC-Authentication-Results";
    public static final String ARC_MESSAGE_SIGNATURE = "ARC-Message-Signature";
    public static final String ARC_SEAL = "ARC-Seal";
    public static final String SHA256RSA = "SHA256withRSA";
    private static final String DNS_RECORD_TYPE = "_domainkey";
    private PublicKeyRetrieverArc _keyRecordRetriever;

    ARCVerifier(PublicKeyRetrieverArc keyRecordRetriever) {
        _keyRecordRetriever = keyRecordRetriever;
    }

    public boolean verifyAms(Field amsField, Message message, String publicKeyDnsRecord) {
        // Extract AMS params
        String amsValue = amsField.getBody();
        Map<String, String> tags = parseTagList(amsValue);

        String signedHeaders = tags.get("h");
        String bodyHash = tags.get("bh");
        String signatureB64 = tags.get("b");
        String b64 = signatureB64
                .replaceAll("\\s+", "")   // remove spaces, tabs, newlines
                .replace(";", "");        // defensive: strip trailing semicolon if present

        if (signedHeaders == null || bodyHash == null) {
            throw new ArcException("AMS missing required tags");
        }

        String amsForSigning = amsValue.replaceFirst(B_TAG_REGEX, "b=");
        // Canonicalize headers listed in h=
        StringBuilder signingData = new StringBuilder();
        for (String hName : signedHeaders.split(":")) {
            hName = hName.trim();
            for (Field f : message.getHeader().getFields(hName)) {
                signingData.append(canonicalizeRegularHeader(f));
            }
        }

        // AMS itself must be included last
        signingData.append(canonicalizeHeader(amsField.getName(), amsForSigning));

        // Build RSA public key from DNS record
        PublicKey publicKey = parsePublicKeyFromDns(publicKeyDnsRecord);

        // Verify signature
        Signature sig = getSignature( publicKey, signingData);

        byte[] signatureBytes = Base64.getDecoder().decode(b64);

        boolean result = false;
        if (sig != null) {
            try {
                result = sig.verify(signatureBytes);
            } catch (SignatureException e) {
                throw new ArcException("Signature verification failed", e);
            }
        }
        return result;
    }

    private Signature getSignature(PublicKey publicKey, StringBuilder signingData)  {
        Signature sig;
        try {
            sig = Signature.getInstance(SHA256RSA);
            sig.initVerify(publicKey);
            String dataToSign = signingData.toString();
            sig.update(dataToSign.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new ArcException("Unsupported signing algorithm when used with public key", e);
        } catch (InvalidKeyException e) {
            throw new ArcException("Invalid key when used with public key", e);
        } catch (SignatureException e) {
            throw new ArcException("Invalid signature when used with public key", e);
        }
        return sig;
    }

    public Map<String, String> parseTagList(String value) {
        Map<String, String> map = new HashMap<>();
        Matcher m = TAG_PATTERN.matcher(value);
        while (m.find()) {
            map.put(m.group(1).trim(), m.group(2).trim());
        }
        return map;
    }

    private String canonicalizeRegularHeader(Field field) {
        String retVal = canonicalizeHeader(field.getName(), field.getBody());
        return retVal + "\r\n";
    }

    private String canonicalizeHeader(String name, String value) {
        // relaxed canonicalization: lowercase field name, unfold spaces, trim
        String n = name.toLowerCase(Locale.ROOT);
        String v = value.replaceAll("[\\r\\n]+", " ")
                .replaceAll("\\s+", " ")
                .trim();
        return n + ":" + v;
    }

    public PublicKey parsePublicKeyFromDns(String dnsRecord) {
        Matcher m = PUBLIC_KEY_PATTERN.matcher(dnsRecord);

        if (!m.find()) {
            throw new IllegalArgumentException("Illegal argument exception -- No p= tag in DNS record");
        }

        String base64Key = m.group(1).replaceAll("\\s+", ""); // remove ALL spaces/newlines
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        PublicKey pubKey;
        try {
            pubKey = KeyFactory.getInstance(RSA).generatePublic(spec);
        } catch (InvalidKeySpecException e) {
            throw new ArcException("Invalid key provided when getting public key", e);
        } catch (NoSuchAlgorithmException e) {
            throw new ArcException("Unsupported algorithm provided when getting public key", e);
        }
        return pubKey;
    }

    public boolean validateArcSetStructure(Map<Integer, List<Field>> arcHeadersByI) {
        for (int i = 1; i <= arcHeadersByI.size(); i++) {
            List<Field> arcSet = arcHeadersByI.get(i);
            if (arcSet == null) { // continuity of instances is broken
                throw new IllegalStateException("ARC Chain validation fails due to i instances not continued after [" + (i - 1) + "] instance.");
            }

            boolean eachOfOne = checkArcSetCompose(arcSet);
            if (!eachOfOne) {
                throw new ArcException("ARC Chain validation fails due to one or more ARC Set headers missing at instance [" + i + "].");
            }

            if (arcSet.size() != 3){
                throw new ArcException("ARC Chain validation fails due to incorrect size of Arc Headers (not 3) at instance [" + i + "].");
            }

            boolean cvOk = checkCv(arcSet, i);
            if (!cvOk) {
                throw new ArcException("ARC Chain validation fails due to cv check failing at instance [" + i + "].");
            }
        }
        return true;
    }

    private boolean checkCv(List<Field> lastArcSet, int instToVerify) {
        Optional<Field> arcSealHeader = lastArcSet.stream().filter(f -> f.getName().equalsIgnoreCase(ARC_SEAL)).findFirst();
        if (arcSealHeader.isPresent()) {
            Map<String, String> tags = parseTagList(arcSealHeader.get().getBody());
            String lastCv = tags.get("cv");
            return (instToVerify == 1 && lastCv.equalsIgnoreCase("none")) ||
                    (instToVerify > 1 && lastCv.equalsIgnoreCase("pass"));
        }
        return false;
    }

    private boolean checkArcSetCompose(List<Field> arcSet) {
        Optional<Field> aar = arcSet.stream().filter(p-> p.getName()
                .equalsIgnoreCase(ARC_AUTHENTICATION_RESULTS)).findFirst();

        Optional<Field> ams = arcSet.stream().filter(p-> p.getName()
                .equalsIgnoreCase(ARC_MESSAGE_SIGNATURE)).findFirst();

        Optional<Field> as = arcSet.stream().filter(p-> p.getName()
                .equalsIgnoreCase(ARC_SEAL)).findFirst();
        return aar.isPresent() && ams.isPresent() && as.isPresent();
    }

    public String buildDnsQuery(Field signedField, String recordType) {
        String retVal = "";
        Map<String, String> tags = parseTagList(signedField.getBody());
        if (tags.isEmpty()) { // we should always have tags on the valid AMS
            return retVal;
        }
        String amsSelector = tags.get("s");
        String amsDomain = tags.get("d");
        if (amsSelector == null || amsDomain == null) { // we should always have these tags on the valid AMS
            return retVal;
        }
        retVal = amsSelector+"."+ recordType+"."+amsDomain;
        return retVal;
    }

    public Map<Integer, List<Field>> getArcHeadersByI(List<Field> headers) {
        Map<Integer, List<Field>> headersByI = new TreeMap<>();
        for (Field f : headers) {
            String name = f.getName().toUpperCase(Locale.ROOT);
            if (name.startsWith("ARC-")) {
                int i = -1;
                String iTag = parseTagGeneric(f.getBody(), "i");
                if (iTag != null) {
                    i = Integer.parseInt(iTag);
                }
                if (i == -1) {
                    throw new IllegalStateException("ARC Header missing i= tag");
                }
                else {
                    headersByI.computeIfAbsent(i, k -> new ArrayList<>()).add(f);
                }
            }
        }
        return headersByI;
    }

    public String canonicalizeBody(String body) {
        body = body.replaceAll("\r\n[\t ]", " ");
        body = body.replaceAll("[\t ]+", " ");
        body = body.trim();
        return body;
    }

    public String parseTagGeneric(String record, String tag) {
        String[] parts = record.split(";");
        for (String part : parts) {
            String trimmed = part.trim();
            if (trimmed.startsWith(tag + "=")) {
                return trimmed.substring((tag + "=").length());
            }
        }
        return null;
    }

    public ArcSealVerifyData buildArcSealSigningData(Map<Integer, List<Field>> headersByI, int targetI) {
        ArcSealVerifyData result = null;
        StringBuilder signingData = new StringBuilder();

        //Iterate over hops in ascending i order, for the last hop, make sure to clear b= tag on the ARC-Seal
        for (Map.Entry<Integer, List<Field>> entry : headersByI.entrySet()) {
            int hopI = entry.getKey();
            if (hopI > targetI) break;

            List<Field> hopFields = entry.getValue();
            Optional<Field> aar = hopFields.stream().filter(p-> p.getName()
                    .equalsIgnoreCase(ARC_AUTHENTICATION_RESULTS)).findFirst();

            Optional<Field> ams = hopFields.stream().filter(p-> p.getName()
                    .equalsIgnoreCase(ARC_MESSAGE_SIGNATURE)).findFirst();

            Optional<Field> as = hopFields.stream().filter(p-> p.getName()
                    .equalsIgnoreCase(ARC_SEAL)).findFirst();

            aar.ifPresent(f -> signingData
                    .append(f.getName().toLowerCase(Locale.ROOT))
                    .append(":").append(canonicalizeBody(f.getBody()))
                    .append("\r\n"));

            ams.ifPresent(f -> signingData
                    .append(f.getName().toLowerCase(Locale.ROOT))
                    .append(":").append(canonicalizeBody(f.getBody()))
                    .append("\r\n"));

            if (hopI == targetI && as.isPresent()) { // this is last hop so we need to clear b= tag on the ARC-Seal Header and not tail it with CRLF
                Field asField = as.get();
                Map<String, String> tags = parseTagList(asField.getBody());
                String signatureB64 = tags.get("b");
                String b64 = signatureB64.replaceAll("\\s+", "").replace(";", "");
                String arcSealBodyClearedB = asField.getBody().replaceAll("\\bb=([^;]*)", "b=");
                signingData.append(asField.getName().toLowerCase(Locale.ROOT))
                        .append(":").append(canonicalizeBody(arcSealBodyClearedB));
                result = new ArcSealVerifyData(b64, signingData.toString());
                break; // we have the target hop, can exit loop
            }
            else { // this is one of the previous hops, not the last one, so we want to preserve b= tag on the ARC-Seal and tail it with CRLF
                as.ifPresent(f -> signingData
                        .append(f.getName().toLowerCase(Locale.ROOT))
                        .append(":").append(canonicalizeBody(f.getBody()))
                        .append("\r\n"));
            }
        }
        return result;
    }

    public Set<Field> extractArcSet(Header messageHeaders, int instance) {
        Set<Field> prevArcSet = null;
        for (Field field : messageHeaders.getFields()) {
            if (field.getName().startsWith("ARC-") && field.getBody().contains("i="+instance)) {
                if (prevArcSet == null) {
                    prevArcSet = new HashSet<>();
                }
                prevArcSet.add(field);
            }
        }
        return prevArcSet;
    }

    public String getTxtDnsRecordByField(Field signedHeader) {
        String dnsQuery = buildDnsQuery(signedHeader, DNS_RECORD_TYPE);
        if (dnsQuery == null || dnsQuery.isEmpty()) return null;     // corrupted AMS - unable to pull PubKey from DNS
        Map<String, String> tags = parseTagList(signedHeader.getBody());
        if (tags.isEmpty()) { // we should always have tags on the valid AMS
            throw new ArcException("Missing tags for dns record") ;
        }
        String amsSelector = tags.get("s");
        String amsDomain = tags.get("d");

        try {
            List<String> results = getPublicKeyRecordRetriever().getRecords("dns/txt", amsSelector, amsDomain);
            if (!results.isEmpty()) {
                return results.get(0);  //Todo: handle multiple records?
            }
        } catch (TempFailException e) {
            throw new RuntimeException(e);
        } catch (PermFailException e) {
            throw new RuntimeException(e);
        }
        return  null;
    }

    protected PublicKeyRetrieverArc getPublicKeyRecordRetriever()
            {
        return _keyRecordRetriever;
    }
}
