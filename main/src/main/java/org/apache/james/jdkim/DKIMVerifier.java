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

import org.apache.james.jdkim.api.BodyHasher;
import org.apache.james.jdkim.api.Headers;
import org.apache.james.jdkim.api.PublicKeyRecord;
import org.apache.james.jdkim.api.PublicKeyRecordRetriever;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.exceptions.FailException;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.exceptions.TempFailException;
import org.apache.james.jdkim.impl.BodyHasherImpl;
import org.apache.james.jdkim.impl.CompoundBodyHasher;
import org.apache.james.jdkim.impl.DNSPublicKeyRecordRetriever;
import org.apache.james.jdkim.impl.Message;
import org.apache.james.jdkim.impl.MultiplexingPublicKeyRecordRetriever;
import org.apache.james.jdkim.tagvalue.PublicKeyRecordImpl;
import org.apache.james.jdkim.tagvalue.SignatureRecordImpl;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class DKIMVerifier extends DKIMCommon {

    private final PublicKeyRecordRetriever publicKeyRecordRetriever;

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

    protected BodyHasherImpl newBodyHasher(SignatureRecord signRecord)
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
        if (records == null || records.isEmpty()) {
            lastError = "no key for signature";
        } else {
            for (String record : records) {
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
     * @param pkr  public key record
     * @param sign signature record
     * @throws PermFailException when the keys are not applicable
     */
    public static void apply(PublicKeyRecord pkr, SignatureRecord sign) throws PermFailException {
        try {
            if (!pkr.getGranularityPattern().matcher(sign.getIdentityLocalPart())
                    .matches()) {
                throw new PermFailException("inapplicable key identity local="
                        + sign.getIdentityLocalPart() + " Pattern: "
                        + pkr.getGranularityPattern().pattern(), sign);
            }

            if (!pkr.isHashMethodSupported(sign.getHashMethod())) {
                throw new PermFailException("inappropriate hash for a="
                        + sign.getHashKeyType() + "/" + sign.getHashMethod(), sign);
            }
            if (!pkr.isKeyTypeSupported(sign.getHashKeyType())) {
                throw new PermFailException("inappropriate key type for a="
                        + sign.getHashKeyType() + "/" + sign.getHashMethod(), sign);
            }

            if (pkr.isDenySubdomains()) {
                if (!sign.getIdentity().toString().toLowerCase().endsWith(
                        ("@" + sign.getDToken()).toLowerCase())) {
                    throw new PermFailException(
                            "AUID in subdomain of SDID is not allowed by the public key record.", sign);
                }
            }
        } catch (IllegalStateException e) {
            throw new PermFailException("Invalid public key: " + e.getMessage(), sign);
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
        for (Iterator<CharSequence> rlm = sign.getRecordLookupMethods().iterator(); key == null
                && rlm.hasNext(); ) {
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
                if (sign != null) lastTempFailure.setRelatedRecord(sign);
                throw lastTempFailure;
            } else if (lastPermFailure != null) {
                if (sign != null) lastPermFailure.setRelatedRecord(sign);
                throw lastPermFailure;
            }            // this is unexpected because the publicKeySelector always returns
            // null or exception
            else {
                throw new PermFailException(
                        "no key for signature [unexpected condition]", sign);
            }
        }
        return key;
    }

    /**
     * Verifies all of the DKIM-Signature records declared in the supplied input
     * stream
     *
     * @param is inputStream
     * @return a list of verified signature records.
     * @throws IOException
     * @throws FailException if no signature can be verified
     */
    public List<SignatureRecord> verify(InputStream is) throws IOException,
            FailException {
        Message message;
        try {
            try {
                message = new Message(is);
            } catch (RuntimeException e) {
                throw e;
            } catch (IOException e) {
                throw e;
            } catch (Exception e1) {
                // This can only be a MimeException but we don't declare to allow usage of
                // DKIMSigner without Mime4J dependency.
                throw new PermFailException("Mime parsing exception: "
                        + e1.getMessage(), e1);
            }
            try {
                return verify(message, message.getBodyInputStream());
            } finally {
                message.dispose();
            }
        } finally {
            is.close();
        }
    }

    public BodyHasher newBodyHasher(Headers messageHeaders) throws FailException {
        List<String> fields = messageHeaders.getFields("DKIM-Signature");
        if (fields == null || fields.isEmpty()) {
            return null;
        }

        // For each DKIM-signature we prepare an hashjob.
        // We calculate all hashes concurrently so to read
        // the inputstream only once.
        Map<String, BodyHasherImpl> bodyHashJobs = new HashMap<String, BodyHasherImpl>();
        Hashtable<String, FailException> signatureExceptions = new Hashtable<String, FailException>();
        for (String signatureField : fields) {
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
                        throw new PermFailException("Invalid signature record: " + e.getMessage(), e);
                    }

                    // Specification say we MAY refuse to verify the signature.
                    if (signatureRecord.getSignatureTimestamp() != null) {
                        long signedTime = signatureRecord.getSignatureTimestamp();
                        long elapsed = (System.currentTimeMillis() / 1000 - signedTime);
                        if (elapsed < -3600 * 24 * 365 * 3) {
                            throw new PermFailException("Signature date is more than "
                                    + -elapsed / (3600 * 24 * 365) + " years in the future.");
                        } else if (elapsed < -3600 * 24 * 30 * 3) {
                            throw new PermFailException("Signature date is more than "
                                    + -elapsed / (3600 * 24 * 30) + " months in the future.");
                        } else if (elapsed < -3600 * 24 * 3) {
                            throw new PermFailException("Signature date is more than "
                                    + -elapsed / (3600 * 24) + " days in the future.");
                        } else if (elapsed < -3600 * 3) {
                            throw new PermFailException("Signature date is more than "
                                    + -elapsed / 3600 + " hours in the future.");
                        } else if (elapsed < -60 * 3) {
                            throw new PermFailException("Signature date is more than "
                                    + -elapsed / 60 + " minutes in the future.");
                        } else if (elapsed < 0) {
                            throw new PermFailException("Signature date is "
                                    + elapsed + " seconds in the future.");
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
                    BodyHasherImpl bhj = newBodyHasher(signatureRecord);

                    bodyHashJobs.put(signatureField, bhj);

                } else {
                    throw new PermFailException(
                            "unexpected bad signature field");
                }
            } catch (TempFailException e) {
                signatureExceptions.put(signatureField, e);
            } catch (PermFailException e) {
                signatureExceptions.put(signatureField, e);
            } catch (RuntimeException e) {
                signatureExceptions.put(signatureField, new PermFailException(
                        "Unexpected exception processing signature", e));
            }
        }

        if (bodyHashJobs.isEmpty()) {
            if (signatureExceptions.size() > 0) {
                throw prepareException(signatureExceptions);
            } else {
                throw new PermFailException("Unexpected condition with " + fields);
            }
        }

        return new CompoundBodyHasher(bodyHashJobs, signatureExceptions);
    }

    /**
     * Verifies all of the DKIM-Signature records declared in the Headers
     * object.
     *
     * @param messageHeaders  parsed headers
     * @param bodyInputStream input stream for the body.
     * @return a list of verified signature records
     * @throws IOException
     * @throws FailException if no signature can be verified
     */
    public List<SignatureRecord> verify(Headers messageHeaders,
                                        InputStream bodyInputStream) throws IOException, FailException {

        BodyHasher bh = newBodyHasher(messageHeaders);

        if (bh == null) return null;

        CompoundBodyHasher cbh = validateBodyHasher(bh);

        // simultaneous computation of all the hashes.
        DKIMCommon.streamCopy(bodyInputStream, cbh.getOutputStream());

        return verify(cbh);
    }

    /**
     * Completes the simultaneous verification of multiple
     * signatures given the previously prepared compound body hasher where
     * the user already written the body to the outputstream and closed it.
     *
     * @param bh the BodyHasher previously obtained by this class.
     * @return a list of valid (verified) signatures or null on null input.
     * @throws FailException if no valid signature is found
     */
    public List<SignatureRecord> verify(BodyHasher bh) throws FailException {
        if (bh == null) return null;
        CompoundBodyHasher cbh = validateBodyHasher(bh);

        return verify(cbh);
    }

    /**
     * Used by public "verify" methods to make sure the input
     * bodyHasher is a CompoundBodyHasher as expected.
     *
     * @param bh the BodyHasher previously obtained by this class.
     * @return a casted CompoundBodyHasher
     * @throws PermFailException if it wasn't a CompoundBodyHasher
     */
    private CompoundBodyHasher validateBodyHasher(BodyHasher bh)
            throws PermFailException {
        if (!(bh instanceof CompoundBodyHasher)) {
            throw new PermFailException("Unexpected BodyHasher type: this is not generated by DKIMVerifier!");
        }

        return (CompoundBodyHasher) bh;
    }

    /**
     * Internal method to complete the simultaneous verification of multiple
     * signatures given the previously prepared compound body hasher where
     * the user already written the body to the outputstream and closed it.
     *
     * @param compoundBodyHasher the BodyHasher previously obtained by this class.
     * @return a list of valid (verified) signatures
     * @throws FailException if no valid signature is found
     */
    private List<SignatureRecord> verify(CompoundBodyHasher compoundBodyHasher)
            throws FailException {
        List<SignatureRecord> verifiedSignatures = new LinkedList<SignatureRecord>();
        for (BodyHasherImpl bhj : compoundBodyHasher.getBodyHashJobs().values()) {
            byte[] computedHash = bhj.getDigest();
            byte[] expectedBodyHash = bhj.getSignatureRecord().getBodyHash();

            if (!Arrays.equals(expectedBodyHash, computedHash)) {
                compoundBodyHasher.getSignatureExceptions()
                        .put(
                                "DKIM-Signature:" + bhj.getSignatureRecord().toString(),
                                new PermFailException(
                                        "Computed bodyhash is different from the expected one"));
            } else {
                verifiedSignatures.add(bhj.getSignatureRecord());
            }
        }

        if (verifiedSignatures.isEmpty()) {
            throw prepareException(compoundBodyHasher.getSignatureExceptions());
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

    /**
     * Given a map of exceptions prepares a human readable exception.
     * This simply return the exception if it is only one, otherwise returns
     * a cumulative exception
     *
     * @param signatureExceptions input exceptions
     * @return the resulting "compact" exception
     */
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

    /**
     * Performs signature verification (excluding the body hash).
     *
     * @param h       the headers
     * @param sign    the signature record
     * @param decoded the expected signature hash
     * @param key     the DKIM public key record
     * @param headers the list of signed headers
     * @throws PermFailException
     */
    private void signatureVerify(Headers h, SignatureRecord sign,
                                 byte[] decoded, PublicKeyRecord key, List<CharSequence> headers)
            throws PermFailException {
        try {
            Signature signature = Signature.getInstance(sign.getHashMethod()
                    .toString().toUpperCase()
                    + "with" + sign.getHashKeyType().toString().toUpperCase());
            PublicKey publicKey;
            try {
                publicKey = key.getPublicKey();
            } catch (IllegalStateException e) {
                throw new PermFailException("Invalid Public Key: " + e.getMessage(), e);
            }
            signature.initVerify(publicKey);

            signatureCheck(h, sign, headers, signature);

            if (!signature.verify(decoded))
                throw new PermFailException("Header signature does not verify", sign);
        } catch (InvalidKeyException e) {
            throw new PermFailException(e.getMessage(), e);
        } catch (NoSuchAlgorithmException e) {
            throw new PermFailException(e.getMessage(), e);
        } catch (SignatureException e) {
            throw new PermFailException(e.getMessage(), e);
        }
    }

}
