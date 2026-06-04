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
package com.ibm.plugin.rules.detection.mbedtls.ssl;

import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.model.factory.IActionFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.mbedtls.MbedTLSAlgorithmNames;
import com.ibm.plugin.rules.detection.mbedtls.MbedTLSArgumentValueFactory;
import com.ibm.plugin.rules.detection.mbedtls.MbedTLSTlsConfigurationFactory;
import com.ibm.plugin.rules.detection.mbedtls.MbedTLSTlsDefaultConfigurationFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/** Detection rules for mbedTLS SSL/TLS configuration and usage APIs. */
public final class MbedTLSSsl {

    private static final String BUNDLE = "MbedTLS";

    private static final IDetectionRule<AstNode> TLS_USAGE =
            protocolRule(
                    new ValueActionFactory<>("TLS"),
                    "mbedtls_ssl_setup",
                    "mbedtls_ssl_handshake",
                    "mbedtls_ssl_read",
                    "mbedtls_ssl_write");

    private static final IDetectionRule<AstNode> TLS_VERSION =
            protocolRule(
                    new MbedTLSArgumentValueFactory(1, MbedTLSAlgorithmNames.TLS_VERSIONS),
                    "mbedtls_ssl_conf_min_tls_version",
                    "mbedtls_ssl_conf_max_tls_version");

    private static final IDetectionRule<AstNode> TLS_DEFAULT_CONFIGURATION =
            protocolRule(
                    new MbedTLSTlsDefaultConfigurationFactory(), "mbedtls_ssl_config_defaults");

    private static final IDetectionRule<AstNode> TLS_CIPHER_SUITES =
            protocolRule(
                    new MbedTLSTlsConfigurationFactory(
                            1, MbedTLSTlsConfigurationFactory.Kind.CIPHER_SUITE),
                    "mbedtls_ssl_conf_ciphersuites");

    private static final IDetectionRule<AstNode> TLS_GROUPS =
            protocolRule(
                    new MbedTLSTlsConfigurationFactory(
                            1, MbedTLSTlsConfigurationFactory.Kind.TLS_GROUP),
                    "mbedtls_ssl_conf_groups");

    private static final IDetectionRule<AstNode> TLS_SIGNATURE_SCHEMES =
            protocolRule(
                    new MbedTLSTlsConfigurationFactory(
                            1, MbedTLSTlsConfigurationFactory.Kind.TLS_SIGNATURE_SCHEME),
                    "mbedtls_ssl_conf_sig_algs");

    private MbedTLSSsl() {
        // private
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                TLS_USAGE,
                TLS_VERSION,
                TLS_DEFAULT_CONFIGURATION,
                TLS_CIPHER_SUITES,
                TLS_GROUPS,
                TLS_SIGNATURE_SCHEMES);
    }

    @Nonnull
    private static IDetectionRule<AstNode> protocolRule(
            @Nonnull IActionFactory<AstNode> factory, String... methods) {
        return new DetectionRuleBuilder<AstNode>()
                .createDetectionRule()
                .forObjectTypes("*")
                .forMethods(methods)
                .shouldBeDetectedAs(factory)
                .withAnyParameters()
                .buildForContext(new ProtocolContext(ProtocolContext.Kind.TLS))
                .inBundle(() -> BUNDLE)
                .withoutDependingDetectionRules();
    }
}
