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

package org.apache.james.jdkim;

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

import org.apache.commons.codec.binary.Base64;

public class TestKeys {
    public static final PrivateKey privateKey = loadPrivateKey("org/apache/james/jdkim/keys/private.key");
    public static final PublicKey publicKey = loadPublicKey("org/apache/james/jdkim/keys/public.pem");
    public static final KeyPair keyPair = new KeyPair(publicKey, privateKey);

    public static final PrivateKey privateKey_2 = loadPrivateKey("org/apache/james/jdkim/keys/private.2.key");
    public static final PublicKey publicKey_2 = loadPublicKey("org/apache/james/jdkim/keys/public.2.pem");
    public static final KeyPair keyPair_2 = new KeyPair(publicKey, privateKey);

    // poor man´s pem loaders, I'm too lazy to pull in bouncy castle
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
        URL resource = TestKeys.class.getClassLoader().getResource(uri);
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
