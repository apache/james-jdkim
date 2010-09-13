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
        this.publicKeyRecordRetriever = new MultiplexingPublicKeyRecordRetriever(
                "dns", new DNSPublicKeyRecordRetriever());
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

    public BodyHasher newBodyHasher(SignatureRecord signRecord)
            throws PermFailException {
        return new BodyHasherImpl(signRecord);
    }

    protected PublicKeyRecordRetriever getPublicKeyRecordRetriever()
            throws PermFailException {
        return publicKeyRecordRetriever;
    }

    public PublicKeyRecord publicKeySelector(List<String> records)
            throws PermFailException {
        String lastError = null;
        if (records == null || records.size() == 0) {
            lastError = "no key for signature";
        } else {
            for (Iterator<String> i = records.iterator(); i.hasNext();) {
                String record = i.next();
                try {
                    PublicKeyRecord pk = newPublicKeyRecord(record);
                    pk.validate();
                    // we expect a single valid record, otherwise the result
                    // is unpredictable.
                    // in case of multiple valid records we use the first one.
                    return pk;
                } catch (IllegalStateException e) {
                    // do this at last.
                    lastError = "invalid key for signature: " + e.getMessage();
                }
            }
        }
        // return PERMFAIL ($error).
        throw new PermFailException(lastError);
    }

    /**
     * asserts applicability of a signature record the a public key record.
     * throws an 
     * 
     * @param pkr public key record
     * @param sign signature record
     * @throws PermFailException when the keys are not applicable
     */
    public static void apply(PublicKeyRecord pkr, SignatureRecord sign) throws PermFailException {
        try {
            if (!pkr.getGranularityPattern().matcher(sign.getIdentityLocalPart())
                    .matches()) {
                throw new PermFailException("inapplicable key identity local="
                        + sign.getIdentityLocalPart() + " Pattern: "
                        + pkr.getGranularityPattern().pattern(), sign.getIdentity().toString());
            }
    
            if (!pkr.isHashMethodSupported(sign.getHashMethod())) {
                throw new PermFailException("inappropriate hash for a="
                        + sign.getHashKeyType() + "/" + sign.getHashMethod(), sign.getIdentity().toString());
            }
            if (!pkr.isKeyTypeSupported(sign.getHashKeyType())) {
                throw new PermFailException("inappropriate key type for a="
                        + sign.getHashKeyType() + "/" + sign.getHashMethod(), sign.getIdentity().toString());
            }
    
            if (pkr.isDenySubdomains()) {
                if (!sign.getIdentity().toString().toLowerCase().endsWith(
                        ("@" + sign.getDToken()).toLowerCase())) {
                    throw new PermFailException(
                            "AUID in subdomain of SDID is not allowed by the public key record.", sign.getIdentity().toString());
                }
            }
        } catch (IllegalArgumentException e) {
            throw new PermFailException("Invalid public key: "+e.getMessage(), sign.getIdentity().toString());
        } catch (IllegalStateException e) {
            throw new PermFailException("Invalid public key: "+e.getMessage(), sign.getIdentity().toString());
        }
    }

    /**
     * Iterates through signature's declared lookup method
     * 
     * @param sign
     *                the signature record
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
        for (Iterator<CharSequence> rlm = sign.getRecordLookupMethods().iterator(); key == null
                && rlm.hasNext();) {
            CharSequence method = rlm.next();
            try {
                PublicKeyRecordRetriever pkrr = getPublicKeyRecordRetriever();
                List<String> records = pkrr.getRecords(method, sign.getSelector()
                        .toString(), sign.getDToken().toString());
                PublicKeyRecord tempKey = publicKeySelector(records);
                // checks wether the key is applicable to the signature
                // TODO check with the IETF group to understand if this is the
                // right thing to do.
                // TODO loggin
                apply(tempKey, sign);
                key = tempKey;
            } catch (TempFailException tf) {
                lastTempFailure = tf;
            } catch (PermFailException pf) {
                lastPermFailure = pf;
            }
        }
        if (key == null) {
            if (lastTempFailure != null) {
                if (sign != null) lastTempFailure.setRelatedRecordIdentity(sign.getIdentity().toString());
                throw lastTempFailure;
            } else if (lastPermFailure != null) {
                if (sign != null) lastPermFailure.setRelatedRecordIdentity(sign.getIdentity().toString());
                throw lastPermFailure;
            }            // this is unexpected because the publicKeySelector always returns
            // null or exception
            else {
                throw new PermFailException(
                        "no key for signature [unexpected condition]", sign.getIdentity().toString());
            }
        }
        return key;
    }

    /**
     * Verifies all of the DKIM-Signature records declared in the supplied input
     * stream
     * 
     * @param is
     *                inputStream
     * @return a list of verified signature records.
     * @throws IOException
     * @throws FailException
     *                 if no signature can be verified
     */
    public List<SignatureRecord> verify(InputStream is) throws IOException,
            FailException {
        Message message;
        try {
            message = new Message(is);
            try {
                return verify(message, message.getBodyInputStream());
            } finally {
                message.dispose();
            }
        } catch (MimeException e1) {
            throw new PermFailException("Mime parsing exception: "
                    + e1.getMessage(), e1);
        } finally {
            is.close();
        }
    }

    /**
     * Verifies all of the DKIM-Signature records declared in the Headers
     * object.
     * 
     * @param messageHeaders
     *                parsed headers
     * @param bodyInputStream
     *                input stream for the body.
     * @return a list of verified signature records
     * @throws IOException
     * @throws FailException
     *                 if no signature can be verified
     */
    public List<SignatureRecord> verify(Headers messageHeaders,
            InputStream bodyInputStream) throws IOException, FailException {
        // System.out.println(message.getFields("DKIM-Signature"));
        List<String> fields = messageHeaders.getFields("DKIM-Signature");
        // if (fields.size() > 1) throw new RuntimeException("here we are!");
        if (fields == null || fields.size() == 0) {
            throw new PermFailException("DKIM-Signature field not found");
        }

        // For each DKIM-signature we prepare an hashjob.
        // We calculate all hashes concurrently so to read
        // the inputstream only once.
        Map<String, BodyHasher> bodyHashJobs = new HashMap<String, BodyHasher>();
        List<OutputStream> outputStreams = new LinkedList<OutputStream>();
        Hashtable<String, FailException> signatureExceptions = new Hashtable<String, FailException>();
        for (Iterator<String> i = fields.iterator(); i.hasNext();) {
            String signatureField = i.next();
            try {
                int pos = signatureField.indexOf(':');
                if (pos > 0) {
                    String v = signatureField.substring(pos + 1, signatureField
                            .length());
                    SignatureRecord signatureRecord;
                    try {
                        signatureRecord = newSignatureRecord(v);
                        // validate
                        signatureRecord.validate();
                    } catch (IllegalStateException e) {
                        throw new PermFailException("Invalid signature record: "+e.getMessage(), e);
                    }

                    // Specification say we MAY refuse to verify the signature.
                    if (signatureRecord.getSignatureTimestamp() != null) {
                        long signedTime = signatureRecord.getSignatureTimestamp().longValue();
                        long elapsed = (System.currentTimeMillis()/1000 - signedTime);
                        if (elapsed < 0) {
                            // throw new IllegalStateException("Signature date is "
                            //        + getTimeMeasure(elapsed) + " in the future.");
                            break;
                        }
                    }

                    // TODO here we could check more parameters for
                    // validation before running a network operation like the
                    // dns lookup.
                    // e.g: the canonicalization method could be checked now.
                    PublicKeyRecord publicKeyRecord = publicRecordLookup(signatureRecord);

                    List<CharSequence> signedHeadersList = signatureRecord.getHeaders();

                    byte[] decoded = signatureRecord.getSignature();
                    signatureVerify(messageHeaders, signatureRecord, decoded,
                            publicKeyRecord, signedHeadersList);

                    // we track all canonicalizations+limit+bodyHash we
                    // see so to be able to check all of them in a single
                    // stream run.
                    BodyHasher bhj = newBodyHasher(signatureRecord);

                    bodyHashJobs.put(signatureField, bhj);
                    outputStreams.add(bhj.getOutputStream());

                } else {
                    throw new PermFailException(
                            "unexpected bad signature field");
                }
            } catch (TempFailException e) {
                signatureExceptions.put(signatureField, e);
            } catch (PermFailException e) {
                signatureExceptions.put(signatureField, e);
            } catch (InvalidKeyException e) {
                signatureExceptions.put(signatureField, new PermFailException(e
                        .getMessage(), e));
            } catch (NoSuchAlgorithmException e) {
                signatureExceptions.put(signatureField, new PermFailException(e
                        .getMessage(), e));
            } catch (SignatureException e) {
                signatureExceptions.put(signatureField, new PermFailException(e
                        .getMessage(), e));
            }
        }

        OutputStream o;
        if (bodyHashJobs.size() == 0) {
            throw prepareException(signatureExceptions);
        } else if (bodyHashJobs.size() == 1) {
            o = ((BodyHasher) bodyHashJobs.values().iterator().next())
                    .getOutputStream();
        } else {
            o = new CompoundOutputStream(outputStreams);
        }

        // simultaneous computation of all the hashes.
        DKIMCommon.streamCopy(bodyInputStream, o);

        List<SignatureRecord> verifiedSignatures = new LinkedList<SignatureRecord>();
        for (Iterator<BodyHasher> i = bodyHashJobs.values().iterator(); i.hasNext();) {
            BodyHasher bhj = i.next();

            byte[] computedHash = bhj.getDigest();
            byte[] expectedBodyHash = bhj.getSignatureRecord().getBodyHash();

            if (!Arrays.equals(expectedBodyHash, computedHash)) {
                signatureExceptions
                        .put(
                                "DKIM-Signature:"+bhj.getSignatureRecord().toString(),
                                new PermFailException(
                                        "Computed bodyhash is different from the expected one"));
            } else {
                verifiedSignatures.add(bhj.getSignatureRecord());
            }
        }

        if (verifiedSignatures.size() == 0) {
            throw prepareException(signatureExceptions);
        } else {
            // There is no access to the signatureExceptions when
            // there is at least one valid signature (JDKIM-14)
            /*
            for (Iterator i = signatureExceptions.keySet().iterator(); i
                    .hasNext();) {
                String f = (String) i.next();
                System.out.println("DKIM-Error:"
                        + ((FailException) signatureExceptions.get(f))
                                .getMessage() + " FIELD: " + f);
            }
            */
            /*
            for (Iterator i = verifiedSignatures.iterator(); i.hasNext();) {
                SignatureRecord sr = (SignatureRecord) i.next();
                System.out.println("DKIM-Pass:" + sr);
            }
            */
            return verifiedSignatures;
        }

    }

    private FailException prepareException(Map<String, FailException> signatureExceptions) {
        if (signatureExceptions.size() == 1) {
            return signatureExceptions.values().iterator()
                    .next();
        } else {
            // TODO loops signatureExceptions to give a more complete
            // response, using nested exception or a compound exception.
            // System.out.println(signatureExceptions);
            return new PermFailException("found " + signatureExceptions.size()
                    + " invalid signatures");
        }
    }

    private void signatureVerify(Headers h, SignatureRecord sign,
            byte[] decoded, PublicKeyRecord key, List<CharSequence> headers)
            throws NoSuchAlgorithmException, InvalidKeyException,
            SignatureException, PermFailException {

        Signature signature = Signature.getInstance(sign.getHashMethod()
                .toString().toUpperCase()
                + "with" + sign.getHashKeyType().toString().toUpperCase());
        signature.initVerify(key.getPublicKey());

        signatureCheck(h, sign, headers, signature);

        if (!signature.verify(decoded))
            throw new PermFailException("Header signature does not verify");
    }

}
