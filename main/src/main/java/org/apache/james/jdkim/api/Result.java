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

package org.apache.james.jdkim.api;

import java.util.Locale;

/**
 * Class to hold results of DKIMVerifier
 */
public class Result {
    private static final String TSPECIALS = "()<>@,;:\\\"/[]?=";

    private final String errorMessage;
    private final String dkimRawField;
    private final SignatureRecord record;
    private final Type type;
    private final String warning;

    /**
     * Result type
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc8601#section-2.7.1">RFC8601 2.7.1</a>
     */
    public enum Type {
        NONE,
        PASS,
        FAIL,
        POLICY,
        NEUTRAL,
        TEMPERROR,
        PERMERROR
    }

    /**
     * Constructor to create a Result instance with error message
     *
     * @param errorMessage Error message, from exception
     * @param dkimRawField The DKIM-Signature field
     * @param record       SignatureRecord
     * @param type         Result type
     */
    public Result(String errorMessage, String dkimRawField, SignatureRecord record, Type type) {
        this.errorMessage = errorMessage;
        this.dkimRawField = dkimRawField;
        this.record = record;
        this.type = type;
        this.warning = null;
    }

    /**
     * Constructor to create a Result instance of a successful verification
     *
     * @param record SignatureRecord
     */
    public Result(SignatureRecord record) {
        this(record, null);
    }

    /**
     * Constructor to create a Result instance of a successful verification the verifier has a concern about
     *
     * @param record  SignatureRecord
     * @param warning The concern, null if none
     */
    public Result(SignatureRecord record, String warning) {
        this.errorMessage = null;
        this.dkimRawField = null;
        this.record = record;
        this.type = Type.PASS;
        this.warning = warning;
    }

    /**
     * Returns a string representing the result, with a reason field
     */
    public String getHeaderTextWithReason() {
        return getHeaderText(true);
    }

    /**
     * Returns a string representing the result
     */
    public String getHeaderText() {
        return getHeaderText(false);
    }

    /**
     * Returns the header text for usage with authentication results header, like defined in RFC7601
     *
     * @param withReason If true, add reason field with error/success message
     * @return String
     */
    private String getHeaderText(boolean withReason) {
        if (record == null) {
            return "";
        }

        String partialSig = "";
        String reasonProp = "";
        if (record.getRawSignature() != null) {
            // base64 ignores FWS: truncate after removing it so the prefix holds 12 base64 characters.
            String signature = sanitize(record.getRawSignature()).replaceAll("[\t ]", "");
            partialSig = " header.b=" + pvalue(signature.substring(0, Math.min(12, signature.length())));
        }

        if (withReason) {
            String reasonMsg;
            switch (type) {
                case PASS:
                    reasonMsg = warning != null ? "valid signature, but " + warning : "valid signature";
                    break;
                case NONE:
                    reasonMsg = "unknown error";
                    break;
                default:
                    reasonMsg = errorMessage != null ? errorMessage : "";
                    break;
            }
            reasonProp = reasonMsg.isEmpty() ? "" : " reason=" + quotedString(sanitize(reasonMsg));
        }

        return String.format("dkim=%s header.d=%s header.s=%s%s%s",
                type.toString().toLowerCase(Locale.US), pvalue(sanitize(record.getDToken())), pvalue(sanitize(record.getSelector())),
                partialSig, reasonProp);
    }

    /**
     * Unfolds the value and drops control characters, which a quoted-string can not hold. Tabs become spaces.
     */
    private static String sanitize(CharSequence value) {
        if (value == null) {
            return "";
        }
        StringBuilder res = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\t') {
                res.append(' ');
            } else if (c >= 0x20 && c != 0x7f) {
                res.append(c);
            }
        }
        return res.toString();
    }

    /**
     * Formats a property value as a RFC 8601 pvalue: an RFC 2045 token as is, a quoted-string otherwise.
     */
    private static String pvalue(String value) {
        return isToken(value) ? value : quotedString(value);
    }

    private static boolean isToken(String value) {
        if (value.isEmpty()) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c <= 0x20 || c >= 0x7f || TSPECIALS.indexOf(c) >= 0) {
                return false;
            }
        }
        return true;
    }

    private static String quotedString(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    /**
     * Get ErrorMessage
     *
     * @return The error message produced when the exception was thrown
     */
    public String getErrorMessage() {
        return errorMessage;
    }

    /**
     * Get the concern the verifier has about a successful verification, for instance an unsigned
     * extra instance of a single-instance field (see {@link VerifierOptions.Builder#withUnsignedDuplicateFieldPolicy}).
     *
     * @return the warning, or null if none
     */
    public String getWarning() {
        return warning;
    }

    /**
     * Get dkim field
     *
     * @return The DKIM-Signature field that was verified
     */
    public String getDkimRawField() {
        return dkimRawField;
    }

    /**
     * @return Returns true if success
     */
    public boolean isSuccess() {
        return type == Type.PASS;
    }

    /**
     * @return Returns true if fail
     */
    public boolean isFail() {
        return !isSuccess();
    }

    /**
     * The resulting SignatureRecord
     *
     * @return SignatureRecord
     */
    public SignatureRecord getRecord() {
        return record;
    }

    /**
     * Result Type
     *
     * @return The result type
     */
    public Type getResultType() {
        return type;
    }

    @Override
    public String toString() {
        return "Result{" +
                "headerText='" + getHeaderText() + '\'' +
                ", errorMessage='" + errorMessage + '\'' +
                ", dkimRawField='" + dkimRawField + '\'' +
                ", type=" + type +
                ", warning='" + warning + '\'' +
                '}';
    }
}
