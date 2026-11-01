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

import static org.apache.james.jdkim.DKIMCommon.signatureCheck;

import org.apache.james.jdkim.api.BodyHasher;
import org.apache.james.jdkim.api.Headers;
import org.apache.james.jdkim.api.PublicKeyRecord;
import org.apache.james.jdkim.api.PublicKeyRecordRetriever;
import org.apache.james.jdkim.api.Result;
import org.apache.james.jdkim.api.SignatureRecord;
import org.apache.james.jdkim.api.UnsignedDuplicateFieldPolicy;
import org.apache.james.jdkim.api.VerifierOptions;
import org.apache.james.jdkim.exceptions.CompositeFailException;
import org.apache.james.jdkim.exceptions.FailException;
import org.apache.james.jdkim.exceptions.PermFailException;
import org.apache.james.jdkim.exceptions.SignatureMismatchException;
import org.apache.james.jdkim.exceptions.TempFailException;
import org.apache.james.jdkim.impl.BodyHasherImpl;
import org.apache.james.jdkim.impl.CompoundBodyHasher;
import org.apache.james.jdkim.impl.Message;
import org.apache.james.jdkim.tagvalue.PublicKeyRecordImpl;
import org.apache.james.jdkim.tagvalue.SignatureRecordImpl;
import org.apache.james.jdkim.tagvalue.SignatureRecordTemplate;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class DKIMVerifier {
    private final List<Result> result = new ArrayList<>();
    private final VerifierOptions options;

    public DKIMVerifier() {
        this(new VerifierOptions.Builder().build());
    }

    /**
     * Constructor with configuration, see {@link VerifierOptions.Builder} for available options.
     *
     * @param verifierOptions An instance of VerifierOptions, use {@link VerifierOptions.Builder}
     */
    public DKIMVerifier(VerifierOptions verifierOptions) {
        this.options = verifierOptions;
    }

    public DKIMVerifier(PublicKeyRecordRetriever publicKeyRecordRetriever) {
        this(new VerifierOptions.Builder().withPublicKeyRecordRetriever(publicKeyRecordRetriever).build());
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
        return options.getPublicKeyRecordRetriever();
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
                if (!sign.getIdentity().toString().toLowerCase(Locale.US).endsWith(
                        ("@" + sign.getDToken()).toLowerCase(Locale.US))) {
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
     * @throws TempFailException For temporary error
     * @throws PermFailException For unrecoverable failure
     */
    public PublicKeyRecord publicRecordLookup(SignatureRecord sign)
            throws TempFailException, PermFailException {
        PublicKeyRecord key = null;
        TempFailException lastTempFailure = null;
        PermFailException lastPermFailure = null;
        // RFC 6376 section 6.1.2: each distinct q= method is queried at most once.
        Set<String> methods = new LinkedHashSet<>();
        for (CharSequence method : sign.getRecordLookupMethods()) {
            methods.add(method.toString());
        }
        for (Iterator<String> rlm = methods.iterator(); key == null
                && rlm.hasNext(); ) {
            String method = rlm.next();
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
                lastTempFailure.setRelatedRecord(sign);
                throw lastTempFailure;
            } else if (lastPermFailure != null) {
                lastPermFailure.setRelatedRecord(sign);
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
     * @throws IOException If error occurs handling data
     * @throws FailException if no signature can be verified
     */
    public List<SignatureRecord> verify(InputStream is) throws IOException,
            FailException {
        Message message;
        try {
            try {
                message = new Message(is);
            } catch (RuntimeException | IOException e) {
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
        // One job per field, even for byte-identical fields: each one gets its own result.
        List<CompoundBodyHasher.Job> jobs = new ArrayList<>();
        int processedSignatures = 0;
        for (int signatureIndex = 0; signatureIndex < fields.size(); signatureIndex++) {
            String signatureField = fields.get(signatureIndex);
            CompoundBodyHasher.Job job = new CompoundBodyHasher.Job(signatureField);
            jobs.add(job);
            // RFC 6376 section 6.1: verifiers MAY limit the number of signatures they try to verify.
            if (processedSignatures >= options.getMaxSignatures()) {
                job.setFailure(new PermFailException("Too many DKIM-Signature fields: only the first "
                        + options.getMaxSignatures() + " are verified"));
                continue;
            }
            processedSignatures++;
            try {
                int pos = signatureField.indexOf(':');
                if (pos > 0) {
                    String v = signatureField.substring(pos + 1);
                    SignatureRecord signatureRecord = null;
                    try {
                        signatureRecord = newSignatureRecord(v);
                    } catch (IllegalStateException e) {
                        throw new PermFailException("Invalid signature record: " + e.getMessage(), signatureRecord, e);
                    }

                    // Specification say we MAY refuse to verify the signature.
                    if (signatureRecord.getSignatureTimestamp() != null) {
                        Instant signedTime = Instant.ofEpochSecond(signatureRecord.getSignatureTimestamp());
                        Instant now = Instant.now();
                        if (signedTime.isAfter(now.plus(options.getClockDriftTolerance()))) {
                            // RFC 6376, Section 3.5 page 25, about clock drift:
                            // Receivers MAY add a 'fudge factor' to allow for such possible drift.
                            Duration diff = Duration.between(now, signedTime);
                            String diffText;
                            if (diff.toMillis() >= 86400000) {
                                diffText = diff.toDays() + " day(s)";
                            } else if (diff.toMillis() >= 3600000) {
                                diffText = diff.toHours() + " hour(s)";
                            } else if (diff.toMillis() >= 60000) {
                                diffText = diff.toMinutes() + " minute(s)";
                            } else {
                                diffText = (diff.toMillis() / 1000) + " second(s)";
                            }
                            throw new PermFailException("Signature date is more than "
                                    + diffText + " in the future.", signatureRecord);
                        }
                    }

                    String unsignedInstance = unsignedSingleInstanceField(messageHeaders, signatureRecord);
                    if (unsignedInstance != null) {
                        if (options.getUnsignedDuplicateFieldPolicy() == UnsignedDuplicateFieldPolicy.REJECT) {
                            throw new PermFailException(unsignedInstance, signatureRecord);
                        } else if (options.getUnsignedDuplicateFieldPolicy() == UnsignedDuplicateFieldPolicy.FLAG) {
                            job.setWarning(unsignedInstance);
                        }
                    }

                    // TODO here we could check more parameters for
                    // validation before running a network operation like the
                    // dns lookup.
                    // e.g: the canonicalization method could be checked now.
                    PublicKeyRecord publicKeyRecord = publicRecordLookup(signatureRecord);

                    List<CharSequence> signedHeadersList = signatureRecord.getHeaders();

                    try {
                        // decoded now so that verify(CompoundBodyHasher) cannot fail on it
                        signatureRecord.getBodyHash();
                        byte[] decoded = signatureRecord.getSignature();
                        signatureVerify(withoutSignature(messageHeaders, signatureIndex), signatureRecord, decoded,
                                publicKeyRecord, signedHeadersList, signatureField.substring(0, pos));
                    } catch (IllegalArgumentException e) {
                        throw new PermFailException("Invalid signature record: " + e.getMessage(), signatureRecord, e);
                    }

                    // we track all canonicalizations+limit+bodyHash we
                    // see so to be able to check all of them in a single
                    // stream run.
                    BodyHasherImpl bhj = newBodyHasher(signatureRecord);

                    job.setBodyHasher(bhj);

                } else {
                    throw new PermFailException(
                            "unexpected bad signature field");
                }
            } catch (TempFailException | PermFailException e) {
                job.setFailure(e);
            } catch (RuntimeException e) {
                job.setFailure(new PermFailException(
                        "Unexpected exception processing signature", e));
            }
        }

        return new CompoundBodyHasher(jobs);
    }

    /**
     * RFC 6376 section 8.15: a single-instance field listed in h=, present more times than h= lists it and
     * more than once, has an unsigned instance that mail clients may display instead of the signed one.
     *
     * @return a description of the first such field, or null if there is none
     */
    private String unsignedSingleInstanceField(Headers messageHeaders, SignatureRecord signatureRecord) {
        if (options.getUnsignedDuplicateFieldPolicy() == UnsignedDuplicateFieldPolicy.ACCEPT) {
            return null;
        }
        Map<String, Integer> signedCounts = new HashMap<>();
        for (CharSequence header : signatureRecord.getHeaders()) {
            signedCounts.merge(header.toString().trim().toLowerCase(Locale.US), 1, Integer::sum);
        }
        for (String name : options.getSingleInstanceFields()) {
            List<String> instances = messageHeaders.getFields(name);
            int present = instances == null ? 0 : instances.size();
            int signed = signedCounts.getOrDefault(name, 0);
            // a field h= does not list is not vouched for by the signature; From: is always listed.
            if (signed > 0 && present > 1 && present > signed) {
                return "the message has " + present + " " + name + " fields and h= signs only " + signed
                        + " (RFC 6376 section 8.15)";
            }
        }
        return null;
    }

    /**
     * The field being verified is hashed implicitly, as the last field (RFC 6376
     * section 3.5): like the signer, which did not have it yet, a DKIM-Signature
     * entry of h= only selects the other DKIM-Signature fields.
     *
     * @param headers        the message headers
     * @param signatureIndex the position of the verified field among the
     *                       DKIM-Signature fields
     */
    private static Headers withoutSignature(Headers headers, int signatureIndex) {
        return new Headers() {
            public List<String> getFields() {
                return headers.getFields();
            }

            public List<String> getFields(String name) {
                List<String> fields = headers.getFields(name);
                if (!"DKIM-Signature".equalsIgnoreCase(name) || signatureIndex >= fields.size()) {
                    return fields;
                }
                List<String> others = new ArrayList<>(fields);
                others.remove(signatureIndex);
                return others;
            }
        };
    }

    /**
     * Verifies all of the DKIM-Signature records declared in the Headers
     * object.
     *
     * @param messageHeaders  parsed headers
     * @param bodyInputStream input stream for the body.
     * @return a list of verified signature records
     * @throws IOException If error occurs handling data
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
        List<SignatureRecord> verifiedSignatures = new LinkedList<>();
        List<FailException> failures = new ArrayList<>();
        for (CompoundBodyHasher.Job job : compoundBodyHasher.getJobs()) {
            BodyHasherImpl bhj = job.getBodyHasher();
            if (bhj != null) {
                byte[] computedHash = bhj.getDigest();
                byte[] expectedBodyHash = bhj.getSignatureRecord().getBodyHash();

                if (!Arrays.equals(expectedBodyHash, computedHash)) {
                    job.setFailure(new SignatureMismatchException(
                            "Computed bodyhash is different from the expected one", bhj.getSignatureRecord()));
                } else {
                    verifiedSignatures.add(bhj.getSignatureRecord());
                    result.add(new Result(bhj.getSignatureRecord(), job.getWarning()));
                    continue;
                }
            }
            failures.add(job.getFailure());
            result.add(resultFromException(job.getSignatureField(), job.getFailure()));
        }

        if (verifiedSignatures.isEmpty()) {
            throw prepareException(failures);
        } else {
            return verifiedSignatures;
        }
    }

    /**
     * Returns the results of all signature checks, success and fail.
     * If a message doesn't have a DKIM-Signature header the result list will
     * be empty. Use {@link Result#getResultType} or {@link Result#isSuccess}
     * to get verification result of each DKIM-Signature check. Call {@link #resetResults}
     * if the same instance of {@code DKIMVerifier} is reused for a new {@code verify} call.
     *
     * @return List of {@link Result} object.
     */
    public List<Result> getResults() {
        return result;
    }

    /**
     * Returns {@code true} if at least one signature is successfully verified.
     * A message pass the DKIM check when at least one signature is valid.
     * This method is DMARC compliant, and should be called after {@code DKIMVerifier.verify}.
     * Use {@link #getResults} to get result details.
     *
     * @return {@code true} if a valid signature is found,
     * {@code false} if there's no valid signature.
     * @see #getResults
     */
    public boolean hasAnyValidSignature() {
        return result.stream().anyMatch(Result::isSuccess);
    }

    /**
     * Clears results list for the DKIMVerifier instance
     */
    public void resetResults() {
        result.clear();
    }

    private Result resultFromException(String signatureField, FailException e) {
        SignatureRecord rec = e.getRelatedRecord();
        if (rec == null) {
            rec = new SignatureRecordTemplate("v=1; d=invalid; h=from; s=invalid; b=invalidsig");
        }

        Result.Type resultType = Result.Type.NONE;
        if (e instanceof TempFailException) {
            resultType = Result.Type.TEMPERROR;
        } else if (e instanceof SignatureMismatchException) {
            // RFC 6376 section 6.1, RFC 8601 section 2.7.1: fail only when the signature does not verify.
            resultType = Result.Type.FAIL;
        } else if (e instanceof PermFailException) {
            // malformed or unsupported signature, missing, revoked or inapplicable key...
            resultType = Result.Type.PERMERROR;
        }
        return new Result(e.getMessage(), signatureField != null ? signatureField : "", rec, resultType);
    }

    /**
     * Given a list of exceptions prepares a human readable exception.
     * This simply return the exception if it is only one, otherwise returns
     * a cumulative exception
     *
     * @param signatureExceptions input exceptions
     * @return the resulting "compact" exception
     */
    private FailException prepareException(List<FailException> signatureExceptions) {
        if (signatureExceptions.size() == 1) {
            return signatureExceptions.get(0);
        } else {
            return new CompositeFailException(signatureExceptions, "found " + signatureExceptions.size()
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
     * @param signatureFieldName the name of the verified field, as written
     * @throws PermFailException If signature or public key validation fails
     */
    private void signatureVerify(Headers h, SignatureRecord sign,
                                 byte[] decoded, PublicKeyRecord key, List<CharSequence> headers,
                                 String signatureFieldName)
            throws PermFailException {
        try {
            Signature signature = Signature.getInstance(sign.getHashMethod()
                    .toString().toUpperCase(Locale.US)
                    + "with" + sign.getHashKeyType().toString().toUpperCase(Locale.US));
            PublicKey publicKey;
            try {
                publicKey = key.getPublicKey();
            } catch (IllegalStateException e) {
                throw new PermFailException("Invalid Public Key: " + e.getMessage(), sign, e);
            }
            signature.initVerify(publicKey);

            signatureCheck(h, sign, headers, signature, signatureFieldName);

            if (!signature.verify(decoded))
                throw new SignatureMismatchException("Header signature does not verify", sign);
        } catch (SignatureException e) {
            // e.g. a b= value whose length does not fit the key: the signature does not verify against it.
            throw new SignatureMismatchException("Header signature does not verify: " + e.getMessage(), sign, e);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new PermFailException(e.getMessage(), sign, e);
        }
    }

}
