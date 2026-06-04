/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 PQCA
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ibm.plugin.rules.detection.mbedtls;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.mapper.model.Cipher;
import com.ibm.mapper.model.CipherSuite;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Protocol;
import com.ibm.mapper.model.PseudorandomNumberGenerator;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.collections.CipherSuiteCollection;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.TestBase;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

class MbedTLSDetectionRulesTest extends TestBase {

    private final List<String> values = new ArrayList<>();
    private final List<INode> nodes = new ArrayList<>();

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/mbedtls/MbedTLSDetectionRulesTestFile.cpp", this);

        assertThat(values)
                .contains(
                        "SHA-256",
                        "SHA-384",
                        "HMAC-SHA256",
                        "HKDF-SHA256",
                        "RSA-PSS-SHA256",
                        "ECDSA-SHA256",
                        "ECDH",
                        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384",
                        "AES-256-GCM",
                        "DES-CBC",
                        "AES-128-CFB128",
                        "HMAC",
                        "CHACHA20-POLY1305",
                        "RAND",
                        "TLSv1.2",
                        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                        "TLS_AES_128_GCM_SHA256",
                        "TLS-GROUPS:x25519",
                        "TLS-GROUPS:secp384r1,x25519",
                        "TLS-SIGNATURE-SCHEMES:ecdsa_secp256r1_sha256",
                        "TLS-SIGNATURE-SCHEMES:rsa_pss_rsae_sha256,ecdsa_secp384r1_sha384",
                        "TLS-DEFAULTS:1.3",
                        "TLS");

        assertThat(nodes).anyMatch(node -> node instanceof MessageDigest);
        assertThat(nodes).anyMatch(node -> node instanceof Mac);
        assertThat(nodes).anyMatch(node -> node instanceof KeyDerivationFunction);
        assertThat(nodes).anyMatch(node -> node instanceof Signature);
        assertThat(nodes).anyMatch(node -> node instanceof KeyAgreement);
        assertThat(nodes).anyMatch(node -> node instanceof Cipher);
        assertThat(nodes).anyMatch(node -> node instanceof PseudorandomNumberGenerator);
        assertThat(nodes).anyMatch(node -> node instanceof TLS);
        assertThat(nodes).anyMatch(node -> node instanceof Protocol);
        assertThat(nodes)
                .filteredOn(TLS.class::isInstance)
                .map(TLS.class::cast)
                .anySatisfy(
                        tls -> {
                            assertThat(tls.getVersion())
                                    .hasValueSatisfying(
                                            version ->
                                                    assertThat(version.asString())
                                                            .isEqualTo("1.3"));
                            assertThat(tls.getCipherSuits())
                                    .hasValueSatisfying(
                                            cipherSuites ->
                                                    assertThat(cipherSuiteNames(cipherSuites))
                                                            .contains(
                                                                    "TLS_AES_256_GCM_SHA384",
                                                                    "TLS_AES_128_GCM_SHA256",
                                                                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                                                                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                                                                    "TLS configuration"));
                            assertThat(tls.getCipherSuits())
                                    .hasValueSatisfying(
                                            cipherSuites ->
                                                    assertThat(
                                                                    cipherSuites
                                                                            .getCollection()
                                                                            .stream()
                                                                            .filter(
                                                                                    cipherSuite ->
                                                                                            cipherSuite
                                                                                                    .getName()
                                                                                                    .equals(
                                                                                                            "TLS_AES_128_GCM_SHA256"))
                                                                            .toList())
                                                            .singleElement()
                                                            .satisfies(
                                                                    cipherSuite -> {
                                                                        assertThat(
                                                                                        cipherSuite
                                                                                                .getAssetCollection())
                                                                                .isEmpty();
                                                                        assertThat(
                                                                                        cipherSuite
                                                                                                .getTlsGroupCollection())
                                                                                .isEmpty();
                                                                    }));
                            assertThat(tls.getCipherSuits())
                                    .hasValueSatisfying(
                                            cipherSuites ->
                                                    assertThat(
                                                                    cipherSuites
                                                                            .getCollection()
                                                                            .stream()
                                                                            .filter(
                                                                                    cipherSuite ->
                                                                                            cipherSuite
                                                                                                    .getName()
                                                                                                    .equals(
                                                                                                            "TLS configuration"))
                                                                            .toList())
                                                            .singleElement()
                                                            .satisfies(
                                                                    cipherSuite -> {
                                                                        assertThat(
                                                                                        cipherSuite
                                                                                                .getTlsGroupCollection())
                                                                                .isPresent();
                                                                        assertThat(
                                                                                        cipherSuite
                                                                                                .getTlsSignatureSchemeCollection())
                                                                                .isPresent();
                                                                    }));
                        });
    }

    @Nonnull
    private static List<String> cipherSuiteNames(@Nonnull CipherSuiteCollection cipherSuites) {
        return cipherSuites.getCollection().stream().map(CipherSuite::getName).toList();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<
                                    SquidCheck<?>,
                                    AstNode,
                                    Symbol,
                                    SquidAstVisitorContext<? extends Grammar>>
                            detectionStore,
            @Nonnull List<INode> translatedNodes) {
        detectionStore.getDetectionValues().forEach(value -> values.add(value.asString()));
        nodes.addAll(translatedNodes);
    }
}
