/******************************************************************************
 * Licensed to the Apache Software Foundation (ASF) under one                 *
 * or more contributor license agreements.  See the NOTICE file               *
 * distributed with this work for additional information                      *
 * regarding copyright ownership.  The ASF licenses this file                 *
 * to you under the Apache License, Version 2.0 (the                          *
 * "License"); you may not use this file except in compliance                 *
 * with the License.  You may obtain a copy of the License at                 *
 *                                                                            *
 *   http://www.apache.org/licenses/LICENSE-2.0                               *
 *                                                                            *
 * Unless required by applicable law or agreed to in writing,                 *
 * software distributed under the License is distributed on an                *
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY                     *
 * KIND, either express or implied.  See the License for the                  *
 * specific language governing permissions and limitations                    *
 * under the License.                                                         *
 ******************************************************************************/

package org.apache.james.arc;

import org.apache.commons.codec.binary.Base64;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class ArcTestKeys {
    public static final PrivateKey privateKeyArc = loadPrivateKey("keys/arc_test_pri.1.key");
    public static final PublicKey publicKeyArc = loadPublicKey("keys/arc_test_pub.1.pem");
    public static final PrivateKey privateKeyDkim = loadPrivateKey("keys/dkim_test_pri.1.key");
    public static final PublicKey publicKeyDkim = loadPublicKey("keys/dkim_test_pub.1.pem");
    public static final KeyPair keyPair = new KeyPair(publicKeyArc, privateKeyArc);

    private static PublicKey loadPublicKey(String uri) {
        try {
            String keyText = readFileContent(uri)
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll(System.lineSeparator(), "");
            byte[] encoded = Base64.decodeBase64(keyText);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String readFileContent(String uri) throws URISyntaxException, IOException {
        URL resource = ArcTestKeys.class.getClassLoader().getResource(uri);
        File file = new File(resource.toURI());
        return new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());
    }

    private static PrivateKey loadPrivateKey(String uri) {
        try {
            String keyText = readFileContent(uri)
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll(System.lineSeparator(), "");
            byte[] encoded = Base64.decodeBase64(keyText);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
