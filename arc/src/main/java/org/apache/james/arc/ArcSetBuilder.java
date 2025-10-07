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
import org.apache.james.mime4j.dom.Header;
import org.apache.james.mime4j.dom.Message;
import org.apache.james.mime4j.message.DefaultMessageWriter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builder class for generating ARC (Authenticated Received Chain) header sets.
 * <p>
 * This class is responsible for constructing and signing ARC-Authentication-Results,
 * ARC-Message-Signature, and ARC-Seal headers for a given email message, using
 * provided templates and cryptographic keys.
 * </p>
 * <p>
 * Usage involves providing the necessary templates, DMARC responses, authentication
 * service, and private key. The {@link #buildArcSet(Message, String, String, String, PublicKeyRetrieverArc)}
 * method generates the ARC headers and returns them as a map.
 * </p>
 */
public class ArcSetBuilder {
    public static final String ARC_ELEMENT = "ARC-element:";
    public static final String ARC_SEAL = "ARC-Seal";
    public static final String ARC_MESSAGE_SIGNATURE = "ARC-Message-Signature";
    public static final String AUTHENTICATION_RESULTS = "Authentication-Results";
    public static final String ARC_AUTHENTICATION_RESULTS = "ARC-Authentication-Results";

    private final PrivateKey _arcPrivateKey;
    private final String _arcAmsTemplate;
    private final String _arcSealTemplate;
    private final String _dmarcResponse;
    private final String _dmarcNonResponse;
    private final String _authService;
    private long _debugTimestamp;

    public ArcSetBuilder(PrivateKey arcPrivateKey, String arcAmsTemplate, String arcSealTemplate,
                         String dmarcResponse, String dmarcNonResponse,
                         String authService, long debugTimestamp) {
        this(arcPrivateKey, arcAmsTemplate, arcSealTemplate, dmarcResponse, dmarcNonResponse, authService);
        _debugTimestamp = debugTimestamp;
    }

    public ArcSetBuilder(PrivateKey arcPrivateKey, String arcAmsTemplate, String arcSealTemplate,
                         String dmarcResponse, String dmarcNonResponse,
                         String authService) {
        _arcAmsTemplate = arcAmsTemplate;
        _arcSealTemplate = arcSealTemplate;
        _arcPrivateKey = arcPrivateKey;
        _dmarcResponse = dmarcResponse;
        _dmarcNonResponse = dmarcNonResponse;
        _authService = authService;
    }

    /**
     * Builds the ARC (Authenticated Received Chain) header set for the given email message.
     * <p>
     * This method generates and signs the ARC-Authentication-Results, ARC-Message-Signature,
     * and ARC-Seal headers using the provided message, HELO, MAIL FROM, and IP address.
     * The headers are constructed using configured templates and cryptographic keys.
     * </p>
     *
     * @param message            the email message to process
     * @param helo               the HELO/EHLO string from the SMTP transaction
     * @param mailFrom           the MAIL FROM address from the SMTP transaction
     * @param ip                 the connecting client IP address
     * @param keyRecordRetriever
     * @return a map containing the generated ARC headers and their values
     * @throws ArcException if ARC header generation or signing fails
     */
    public Map<String, String> buildArcSet(Message message, String helo, String mailFrom, String ip, PublicKeyRetrieverArc keyRecordRetriever) {
        Map <String, String> arcHeaders = new HashMap<>();

        try {
            Header headers = message.getHeader();
            ARCChainValidator arcChainValidator = new ARCChainValidator(keyRecordRetriever);
            AuthResultsBuilder authResultsBuilder = new AuthResultsBuilder(_dmarcResponse, _dmarcNonResponse, _authService, keyRecordRetriever);
            String cv = arcChainValidator.validateArcChain(message);
            int instance = arcChainValidator.getCurrentInstance(headers);

            //Build ARC-Authentication-Results header
            String arHeaderValue = authResultsBuilder.getAuthResultsHeader(message, helo, mailFrom,ip);
            if (arHeaderValue == null){
                throw new ArcException("Unable to build Authentication-Results header");
            }

            arcHeaders.put(AUTHENTICATION_RESULTS, arHeaderValue);
            Map<String, String> headersToSeal = new LinkedHashMap<>();
            String aarHeaderValue = "i=" + instance + "; " + arHeaderValue.trim();

            arcHeaders.put(ARC_AUTHENTICATION_RESULTS, aarHeaderValue);
            headersToSeal.put(ARC_AUTHENTICATION_RESULTS, aarHeaderValue);
            DefaultMessageWriter writer = new DefaultMessageWriter();
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            writer.writeMessage(message,os);

            Map<String, Object> fmContext = new HashMap<>();
            fmContext.put("instance", instance);
            long timestamp = Instant.now().getEpochSecond();
            if (_debugTimestamp != 0) {
                timestamp = _debugTimestamp;
            }
            fmContext.put("timestamp", Long.toString(timestamp));
            fmContext.put("cv", cv);

            //Build and add ARC-AMS header
            String amsTemplate = mergeTemplate(_arcAmsTemplate, fmContext);
            ARCSigner amsSigner = new ARCSigner(amsTemplate, _arcPrivateKey);
            String amsHeader = amsSigner.generateAms(new ByteArrayInputStream(os.toByteArray()));
            String amsValue = amsHeader.split(ARC_ELEMENT)[1];
            arcHeaders.put(ARC_MESSAGE_SIGNATURE, amsValue);
            headersToSeal.put(ARC_MESSAGE_SIGNATURE, amsValue);

            //Build and add ARC-Seal header
            String asTemplate = mergeTemplate(_arcSealTemplate, fmContext);
            ARCSigner asSigner = new ARCSigner(asTemplate, _arcPrivateKey);
            String asHeader = asSigner.sealHeaders(headersToSeal );
            String asValue = asHeader.split(ARC_ELEMENT)[1];
            arcHeaders.put(ARC_SEAL, asValue);
        }
        catch (Exception ex){
            throw new ArcException("Unable to generate ARC Seal", ex);
        }
        return arcHeaders;
    }

    private String mergeTemplate(String templateString, Map<String, Object> context) throws IOException {
        try (StringWriter writer = new StringWriter()) {
            freemarker.template.Configuration cfg = new freemarker.template.Configuration(freemarker.template.Configuration.VERSION_2_3_31);
            cfg.setTemplateLoader(new freemarker.cache.StringTemplateLoader());
            freemarker.cache.StringTemplateLoader loader = (freemarker.cache.StringTemplateLoader) cfg.getTemplateLoader();
            loader.putTemplate("template", templateString);
            freemarker.template.Template template = cfg.getTemplate("template");
            template.process(context, writer);
            return writer.toString();
        } catch (freemarker.template.TemplateException e) {
            throw new IOException("Error merging template", e);
        }
    }
}
