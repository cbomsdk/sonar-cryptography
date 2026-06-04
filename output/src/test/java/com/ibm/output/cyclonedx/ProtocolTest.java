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
package com.ibm.output.cyclonedx;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.mapper.ssl.CipherSuiteMapper;
import com.ibm.mapper.model.CipherSuite;
import com.ibm.mapper.model.Identifier;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.TlsGroup;
import com.ibm.mapper.model.TlsSignatureScheme;
import com.ibm.mapper.model.Version;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.collections.AssetCollection;
import com.ibm.mapper.model.collections.CipherSuiteCollection;
import com.ibm.mapper.model.collections.IdentifierCollection;
import com.ibm.mapper.model.collections.TlsGroupCollection;
import com.ibm.mapper.model.collections.TlsSignatureSchemeCollection;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.protocol.IPSec;
import com.ibm.mapper.model.protocol.TLS;
import java.util.List;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.component.crypto.AlgorithmProperties;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.ProtocolProperties;
import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.cyclonedx.model.component.crypto.enums.Mode;
import org.cyclonedx.model.component.crypto.enums.Primitive;
import org.cyclonedx.model.component.crypto.enums.ProtocolType;
import org.junit.jupiter.api.Test;

class ProtocolTest extends TestBase {

    @Test
    void base() {
        this.assertsNode(
                () -> new TLS(new Version("1.3", detectionLocation)),
                bom -> {
                    assertThat(bom.getComponents()).hasSize(1);
                    assertThat(bom.getComponents())
                            .anyMatch(
                                    component -> {
                                        asserts(component.getEvidence());
                                        CryptoProperties c = component.getCryptoProperties();
                                        return component.getName().equals("TLSv1.3")
                                                && c.getProtocolProperties()
                                                        .getType()
                                                        .equals(ProtocolType.TLS)
                                                && c.getProtocolProperties()
                                                        .getVersion()
                                                        .equals("1.3");
                                    });
                });
    }

    @Test
    void cipherSuite() {
        this.assertsNode(
                () -> {
                    final CipherSuite cipherSuite =
                            new CipherSuite(
                                    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", detectionLocation);
                    final DH dh = new DH(KeyAgreement.class, detectionLocation);
                    final AES aes = new AES(256, new CBC(detectionLocation), detectionLocation);
                    final DSA dsa = new DSA(new SHA2(256, detectionLocation));
                    dsa.put(new Oid("2.16.840.1.101.3.4.3.2", detectionLocation));
                    final AssetCollection assetCollection =
                            new AssetCollection(List.of(dh, aes, dsa));
                    final IdentifierCollection identifierCollection =
                            new IdentifierCollection(
                                    List.of(
                                            new Identifier("0x00", detectionLocation),
                                            new Identifier("0x6A", detectionLocation)));
                    cipherSuite.put(assetCollection);
                    cipherSuite.put(identifierCollection);
                    return cipherSuite;
                },
                bom -> {
                    assertThat(bom.getComponents()).hasSize(5);
                    assertThat(bom.getComponents().stream().map(Component::getName))
                            .contains("SHA256withDSA", "SHA256", "AES256-CBC", "TLS", "DH");

                    for (Component component : bom.getComponents()) {
                        asserts(component.getEvidence());
                        assertThat(component.getCryptoProperties()).isNotNull();
                        final CryptoProperties cryptoProperties = component.getCryptoProperties();

                        if (cryptoProperties.getAssetType().equals(AssetType.ALGORITHM)) {
                            assertThat(cryptoProperties.getAlgorithmProperties()).isNotNull();
                            final AlgorithmProperties algorithmProperties =
                                    cryptoProperties.getAlgorithmProperties();
                            if (algorithmProperties.getPrimitive().equals(Primitive.SIGNATURE)) {
                                assertThat(component.getName()).isEqualTo("SHA256withDSA");
                                assertThat(cryptoProperties.getOid())
                                        .isEqualTo("2.16.840.1.101.3.4.3.2");
                            } else if (algorithmProperties.getPrimitive().equals(Primitive.HASH)) {
                                assertThat(component.getName()).isEqualTo("SHA256");
                                assertThat(algorithmProperties.getParameterSetIdentifier())
                                        .isEqualTo("256");
                            } else if (algorithmProperties
                                    .getPrimitive()
                                    .equals(Primitive.KEY_AGREE)) {
                                assertThat(component.getName()).isEqualTo("DH");
                                assertThat(cryptoProperties.getOid())
                                        .isEqualTo("1.2.840.113549.1.3.1");
                            } else if (algorithmProperties
                                    .getPrimitive()
                                    .equals(Primitive.BLOCK_CIPHER)) {
                                assertThat(component.getName()).isEqualTo("AES256-CBC");
                                assertThat(algorithmProperties.getMode()).isEqualTo(Mode.CBC);
                                assertThat(algorithmProperties.getParameterSetIdentifier())
                                        .isEqualTo("256");
                            } else {
                                throw new AssertionError();
                            }
                        } else if (cryptoProperties.getAssetType().equals(AssetType.PROTOCOL)) {
                            assertThat(cryptoProperties.getProtocolProperties()).isNotNull();
                            final ProtocolProperties protocolProperties =
                                    cryptoProperties.getProtocolProperties();
                            assertThat(protocolProperties.getType()).isEqualTo(ProtocolType.TLS);
                            assertThat(protocolProperties.getVersion()).isNull();
                            assertThat(protocolProperties.getCipherSuites()).isNotNull();
                            assertThat(protocolProperties.getCipherSuites()).hasSize(1);

                            final org.cyclonedx.model.component.crypto.CipherSuite cipherSuite =
                                    protocolProperties.getCipherSuites().get(0);
                            assertThat(cipherSuite.getName())
                                    .isEqualTo("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256");

                            assertThat(cipherSuite.getAlgorithms()).hasSize(3);
                            assertThat(cipherSuite.getIdentifiers()).contains("0x00", "0x6A");
                        }
                    }
                });
    }

    @Test
    void protocolWithCipherSuite() {
        this.assertsNode(
                () -> {
                    final TLS tls = new TLS(new Version("1.3", detectionLocation));

                    final CipherSuite cipherSuite =
                            new CipherSuite(
                                    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", detectionLocation);
                    final DH dh = new DH(KeyAgreement.class, detectionLocation);
                    final AES aes = new AES(256, new CBC(detectionLocation), detectionLocation);
                    final DSA dsa = new DSA(new SHA2(256, detectionLocation));
                    dsa.put(new Oid("2.16.840.1.101.3.4.3.2", detectionLocation));
                    final AssetCollection assetCollection =
                            new AssetCollection(List.of(dh, aes, dsa));
                    final IdentifierCollection identifierCollection =
                            new IdentifierCollection(
                                    List.of(
                                            new Identifier("0x00", detectionLocation),
                                            new Identifier("0x6A", detectionLocation)));
                    cipherSuite.put(assetCollection);
                    cipherSuite.put(identifierCollection);

                    tls.put(new CipherSuiteCollection(List.of(cipherSuite)));
                    return tls;
                },
                bom -> {
                    assertThat(bom.getComponents()).hasSize(5);
                    assertThat(bom.getComponents().stream().map(Component::getName))
                            .contains("SHA256withDSA", "SHA256", "AES256-CBC", "TLSv1.3", "DH");

                    for (Component component : bom.getComponents()) {
                        asserts(component.getEvidence());
                        assertThat(component.getCryptoProperties()).isNotNull();
                        final CryptoProperties cryptoProperties = component.getCryptoProperties();

                        if (cryptoProperties.getAssetType().equals(AssetType.ALGORITHM)) {
                            assertThat(cryptoProperties.getAlgorithmProperties()).isNotNull();
                            final AlgorithmProperties algorithmProperties =
                                    cryptoProperties.getAlgorithmProperties();
                            if (algorithmProperties.getPrimitive().equals(Primitive.SIGNATURE)) {
                                assertThat(component.getName()).isEqualTo("SHA256withDSA");
                                assertThat(cryptoProperties.getOid())
                                        .isEqualTo("2.16.840.1.101.3.4.3.2");
                            } else if (algorithmProperties.getPrimitive().equals(Primitive.HASH)) {
                                assertThat(component.getName()).isEqualTo("SHA256");
                                assertThat(algorithmProperties.getParameterSetIdentifier())
                                        .isEqualTo("256");
                            } else if (algorithmProperties
                                    .getPrimitive()
                                    .equals(Primitive.KEY_AGREE)) {
                                assertThat(component.getName()).isEqualTo("DH");
                                assertThat(cryptoProperties.getOid())
                                        .isEqualTo("1.2.840.113549.1.3.1");
                            } else if (algorithmProperties
                                    .getPrimitive()
                                    .equals(Primitive.BLOCK_CIPHER)) {
                                assertThat(component.getName()).isEqualTo("AES256-CBC");
                                assertThat(algorithmProperties.getMode()).isEqualTo(Mode.CBC);
                                assertThat(algorithmProperties.getParameterSetIdentifier())
                                        .isEqualTo("256");
                            } else {
                                throw new AssertionError();
                            }
                        } else if (cryptoProperties.getAssetType().equals(AssetType.PROTOCOL)) {
                            assertThat(cryptoProperties.getProtocolProperties()).isNotNull();
                            final ProtocolProperties protocolProperties =
                                    cryptoProperties.getProtocolProperties();
                            assertThat(protocolProperties.getType()).isEqualTo(ProtocolType.TLS);
                            assertThat(protocolProperties.getVersion()).isEqualTo("1.3");
                            assertThat(protocolProperties.getCipherSuites()).isNotNull();
                            assertThat(protocolProperties.getCipherSuites()).hasSize(1);
                            assertThat(protocolProperties.getCryptoRefArray()).isNull();

                            final org.cyclonedx.model.component.crypto.CipherSuite cipherSuite =
                                    protocolProperties.getCipherSuites().get(0);
                            assertThat(cipherSuite.getName())
                                    .isEqualTo("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256");

                            assertThat(cipherSuite.getAlgorithms()).hasSize(3);
                            assertThat(cipherSuite.getIdentifiers()).contains("0x00", "0x6A");
                        }
                    }
                });
    }

    @Test
    void protocolWithCipherSuiteTlsExtensions() {
        this.assertsNode(
                () -> {
                    final TLS tls = new TLS(detectionLocation);
                    final CipherSuite cipherSuite =
                            new CipherSuite("TLS_AES_128_GCM_SHA256", detectionLocation);
                    cipherSuite.put(
                            new TlsGroupCollection(
                                    List.of(new TlsGroup("x25519", detectionLocation))));
                    cipherSuite.put(
                            new TlsSignatureSchemeCollection(
                                    List.of(
                                            new TlsSignatureScheme(
                                                    "ecdsa_secp256r1_sha256", detectionLocation))));
                    tls.put(new CipherSuiteCollection(List.of(cipherSuite)));
                    return tls;
                },
                bom -> {
                    assertThat(bom.getComponents())
                            .filteredOn(component -> component.getName().equals("TLS"))
                            .hasSize(1);
                    final Component component =
                            bom.getComponents().stream()
                                    .filter(tls -> tls.getName().equals("TLS"))
                                    .findFirst()
                                    .orElseThrow();
                    assertThat(component.getName()).isEqualTo("TLS");
                    final ProtocolProperties protocolProperties =
                            component.getCryptoProperties().getProtocolProperties();
                    assertThat(protocolProperties.getType()).isEqualTo(ProtocolType.TLS);
                    assertThat(protocolProperties.getCipherSuites()).hasSize(1);
                    final org.cyclonedx.model.component.crypto.CipherSuite cipherSuite =
                            protocolProperties.getCipherSuites().get(0);
                    assertThat(cipherSuite.getName()).isEqualTo("TLS_AES_128_GCM_SHA256");
                    assertThat(cipherSuite.getTlsGroups()).containsExactly("x25519");
                    assertThat(cipherSuite.getTlsSignatureSchemes())
                            .containsExactly("ecdsa_secp256r1_sha256");
                });
    }

    @Test
    void mergesProtocolPropertiesForDuplicateTlsComponents() {
        this.assertsNodes(
                () -> {
                    final TLS genericTls = new TLS(detectionLocation);
                    final TLS configuredTls = new TLS(detectionLocation);
                    final CipherSuite cipherSuite =
                            new CipherSuiteMapper()
                                    .parse("TLS_AES_128_GCM_SHA256", detectionLocation)
                                    .filter(CipherSuite.class::isInstance)
                                    .map(CipherSuite.class::cast)
                                    .orElseThrow();
                    configuredTls.put(new CipherSuiteCollection(List.of(cipherSuite)));
                    return List.of(genericTls, configuredTls);
                },
                bom -> {
                    assertThat(bom.getComponents())
                            .filteredOn(component -> component.getName().equals("TLS"))
                            .hasSize(1);
                    final Component component =
                            bom.getComponents().stream()
                                    .filter(tls -> tls.getName().equals("TLS"))
                                    .findFirst()
                                    .orElseThrow();
                    assertThat(component.getName()).isEqualTo("TLS");
                    final ProtocolProperties protocolProperties =
                            component.getCryptoProperties().getProtocolProperties();
                    assertThat(protocolProperties.getType()).isEqualTo(ProtocolType.TLS);
                    assertThat(protocolProperties.getCipherSuites()).hasSize(1);
                    final org.cyclonedx.model.component.crypto.CipherSuite cipherSuite =
                            protocolProperties.getCipherSuites().get(0);
                    assertThat(cipherSuite.getName()).isEqualTo("TLS_AES_128_GCM_SHA256");
                    assertThat(cipherSuite.getAlgorithms()).isNotEmpty();
                    assertThat(protocolProperties.getCryptoRefArray()).isNull();
                });
    }

    @Test
    void keepsTlsConfigurationCipherSuiteSeparateFromConcreteCipherSuites() {
        this.assertsNodes(
                () -> {
                    final TLS cipherSuiteTls = new TLS(detectionLocation);
                    cipherSuiteTls.put(
                            new CipherSuiteCollection(
                                    List.of(
                                            new CipherSuite(
                                                    "TLS_AES_128_GCM_SHA256", detectionLocation))));

                    final CipherSuite tlsConfiguration =
                            new CipherSuite("TLS configuration", detectionLocation);
                    tlsConfiguration.put(
                            new TlsGroupCollection(
                                    List.of(new TlsGroup("x25519", detectionLocation))));
                    tlsConfiguration.put(
                            new TlsSignatureSchemeCollection(
                                    List.of(
                                            new TlsSignatureScheme(
                                                    "ecdsa_secp256r1_sha256", detectionLocation))));
                    final TLS configuredTls = new TLS(detectionLocation);
                    configuredTls.put(new CipherSuiteCollection(List.of(tlsConfiguration)));

                    return List.of(cipherSuiteTls, configuredTls);
                },
                bom -> {
                    assertThat(bom.getComponents()).hasSize(1);
                    final ProtocolProperties protocolProperties =
                            bom.getComponents()
                                    .get(0)
                                    .getCryptoProperties()
                                    .getProtocolProperties();
                    assertThat(protocolProperties.getCipherSuites()).hasSize(2);
                    final org.cyclonedx.model.component.crypto.CipherSuite cipherSuite =
                            protocolProperties.getCipherSuites().stream()
                                    .filter(
                                            suite ->
                                                    suite.getName()
                                                            .equals("TLS_AES_128_GCM_SHA256"))
                                    .findFirst()
                                    .orElseThrow();
                    assertThat(cipherSuite.getName()).isEqualTo("TLS_AES_128_GCM_SHA256");
                    assertThat(cipherSuite.getTlsGroups()).isNullOrEmpty();
                    assertThat(cipherSuite.getTlsSignatureSchemes()).isNullOrEmpty();
                    final org.cyclonedx.model.component.crypto.CipherSuite configuration =
                            protocolProperties.getCipherSuites().stream()
                                    .filter(suite -> suite.getName().equals("TLS configuration"))
                                    .findFirst()
                                    .orElseThrow();
                    assertThat(configuration.getTlsGroups()).containsExactly("x25519");
                    assertThat(configuration.getTlsSignatureSchemes())
                            .containsExactly("ecdsa_secp256r1_sha256");
                });
    }

    @Test
    void explicitTlsConfigurationOverridesDefaultPresetValues() {
        this.assertsNodes(
                () -> {
                    final CipherSuite defaultCipherSuite =
                            new CipherSuite("TLS_AES_256_GCM_SHA384", detectionLocation);
                    final CipherSuite defaultConfiguration =
                            new CipherSuite("TLS configuration", detectionLocation);
                    defaultConfiguration.put(
                            new TlsGroupCollection(
                                    List.of(
                                            new TlsGroup("x25519", detectionLocation),
                                            new TlsGroup("secp256r1", detectionLocation))));
                    defaultConfiguration.put(
                            new TlsSignatureSchemeCollection(
                                    List.of(
                                            new TlsSignatureScheme(
                                                    "rsa_pss_rsae_sha256", detectionLocation),
                                            new TlsSignatureScheme(
                                                    "ecdsa_secp256r1_sha256", detectionLocation))));
                    final TLS defaultTls = new TLS(detectionLocation);
                    defaultTls.put(new Version("1.3", detectionLocation));
                    defaultTls.put(
                            new CipherSuiteCollection(
                                    List.of(defaultCipherSuite, defaultConfiguration)));

                    final CipherSuite explicitCipherSuite =
                            new CipherSuiteMapper()
                                    .parse("TLS_AES_128_GCM_SHA256", detectionLocation)
                                    .map(CipherSuite.class::cast)
                                    .orElseThrow();
                    final CipherSuite explicitConfiguration =
                            new CipherSuite("TLS configuration", detectionLocation);
                    explicitConfiguration.put(
                            new TlsGroupCollection(
                                    List.of(new TlsGroup("x25519", detectionLocation))));
                    explicitConfiguration.put(
                            new TlsSignatureSchemeCollection(
                                    List.of(
                                            new TlsSignatureScheme(
                                                    "ecdsa_secp256r1_sha256", detectionLocation))));
                    final TLS explicitTls = new TLS(detectionLocation);
                    explicitTls.put(new Version("1.2", detectionLocation));
                    explicitTls.put(
                            new CipherSuiteCollection(
                                    List.of(explicitCipherSuite, explicitConfiguration)));

                    return List.of(defaultTls, explicitTls);
                },
                bom -> {
                    final ProtocolProperties protocolProperties =
                            bom.getComponents().stream()
                                    .filter(component -> component.getName().equals("TLS"))
                                    .findFirst()
                                    .orElseThrow()
                                    .getCryptoProperties()
                                    .getProtocolProperties();
                    assertThat(protocolProperties.getVersion()).isEqualTo("1.2");
                    assertThat(protocolProperties.getCipherSuites()).hasSize(2);
                    assertThat(
                                    protocolProperties.getCipherSuites().stream()
                                            .map(suite -> suite.getName()))
                            .containsExactlyInAnyOrder(
                                    "TLS_AES_128_GCM_SHA256", "TLS configuration");
                    final org.cyclonedx.model.component.crypto.CipherSuite cipherSuite =
                            protocolProperties.getCipherSuites().stream()
                                    .filter(
                                            suite ->
                                                    suite.getName()
                                                            .equals("TLS_AES_128_GCM_SHA256"))
                                    .findFirst()
                                    .orElseThrow();
                    assertThat(cipherSuite.getAlgorithms()).isNotEmpty();
                    final org.cyclonedx.model.component.crypto.CipherSuite configuration =
                            protocolProperties.getCipherSuites().stream()
                                    .filter(suite -> suite.getName().equals("TLS configuration"))
                                    .findFirst()
                                    .orElseThrow();
                    assertThat(configuration.getTlsGroups()).containsExactly("x25519");
                    assertThat(configuration.getTlsSignatureSchemes())
                            .containsExactly("ecdsa_secp256r1_sha256");
                });
    }

    @Test
    void protocolOther() {
        this.assertsNode(
                () -> {
                    final IPSec ipsec = new IPSec(detectionLocation);
                    ipsec.put(new AES(128, new CBC(detectionLocation), detectionLocation));
                    ipsec.put(new RSA(detectionLocation));
                    return ipsec;
                },
                bom -> {
                    assertThat(bom.getComponents()).hasSize(3);
                    assertThat(bom.getComponents().stream().map(Component::getName))
                            .contains("AES128-CBC", "RSA", "IPSec");

                    for (Component component : bom.getComponents()) {
                        asserts(component.getEvidence());
                        assertThat(component.getCryptoProperties()).isNotNull();
                        final CryptoProperties cryptoProperties = component.getCryptoProperties();
                        if (cryptoProperties.getAssetType().equals(AssetType.PROTOCOL)) {
                            assertThat(component.getName()).isEqualTo("IPSec");
                            assertThat(cryptoProperties.getProtocolProperties()).isNotNull();
                            final ProtocolProperties protocolProperties =
                                    cryptoProperties.getProtocolProperties();
                            assertThat(protocolProperties.getType()).isEqualTo(ProtocolType.IPSEC);
                            assertThat(protocolProperties.getVersion()).isNull();
                            assertThat(protocolProperties.getCipherSuites()).isNull();
                            assertThat(protocolProperties.getCryptoRefArray()).isNull();
                        }
                    }
                    assertThat(bom.getDependencies())
                            .anySatisfy(
                                    dependency ->
                                            assertThat(dependency.getDependencies()).hasSize(2));
                });
    }
}
