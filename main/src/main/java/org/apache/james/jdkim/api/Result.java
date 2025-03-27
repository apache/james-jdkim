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

/**
 * Class to hold results of DKIMVerifier
 */
public class Result {
    private final String errorMessage;
    private final String dkimRawField;
    private final SignatureRecord record;
    private final Type type;

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
    }

    /**
     * Constructor to create a Result instance of a successful verification
     *
     * @param record SignatureRecord
     */
    public Result(SignatureRecord record) {
        this.errorMessage = null;
        this.dkimRawField = null;
        this.record = record;
        this.type = Type.PASS;
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
            if (record.getRawSignature().length() >= 12) {
                partialSig = " header.b=" + record.getRawSignature().subSequence(0, 12);
            } else {
                partialSig = " header.b=" + record.getRawSignature();
            }
        }

        if (withReason) {
            String reasonMsg;
            switch (type) {
                case PASS:
                    reasonMsg = "valid signature";
                    break;
                case NONE:
                    reasonMsg = "unknown error";
                    break;
                default:
                    reasonMsg = errorMessage != null ? errorMessage : "";
                    break;
            }
            reasonProp = reasonMsg.isEmpty() ? "" : String.format(" reason=\"%s\"", reasonMsg);
        }

        return String.format("dkim=%s header.d=%s header.s=%s%s%s",
                type.toString().toLowerCase(), record.getDToken(), record.getSelector(), partialSig, reasonProp);
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
                '}';
    }
}
