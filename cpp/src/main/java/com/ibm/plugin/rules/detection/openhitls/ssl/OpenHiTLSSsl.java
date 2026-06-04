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
package com.ibm.plugin.rules.detection.openhitls.ssl;

import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.model.factory.IActionFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.openhitls.OpenHiTLSAlgorithmNames;
import com.ibm.plugin.rules.detection.openhitls.OpenHiTLSArgumentValueFactory;
import com.ibm.plugin.rules.detection.openhitls.OpenHiTLSTlsConfigurationFactory;
import com.ibm.plugin.rules.detection.openhitls.OpenHiTLSTlsDefaultConfigurationFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/** Detection rules for openHiTLS TLS configuration and usage APIs. */
public final class OpenHiTLSSsl {

    private static final String BUNDLE = "openHiTLS";

    private static final IDetectionRule<AstNode> TLS_USAGE =
            protocolRule(
                    new ValueActionFactory<>("TLS"),
                    "HITLS_New",
                    "HITLS_Connect",
                    "HITLS_Accept",
                    "HITLS_Read",
                    "HITLS_Write");

    private static final IDetectionRule<AstNode> TLS_VERSION =
            protocolRule(
                    new OpenHiTLSArgumentValueFactory(1, OpenHiTLSAlgorithmNames.TLS_VERSIONS),
                    "HITLS_CFG_SetMinProtoVersion",
                    "HITLS_CFG_SetMaxProtoVersion",
                    "HITLS_CFG_SetVersionSupport",
                    "HITLS_CFG_SetVersion",
                    "HITLS_SetMinProtoVersion",
                    "HITLS_SetMaxProtoVersion",
                    "HITLS_SetVersionSupport",
                    "HITLS_SetVersion");

    private static final IDetectionRule<AstNode> TLS_DEFAULT_CONFIGURATION =
            protocolRule(
                    new OpenHiTLSTlsDefaultConfigurationFactory(),
                    "HITLS_CFG_NewTLS12Config",
                    "HITLS_CFG_ProviderNewTLS12Config",
                    "HITLS_CFG_NewTLS13Config",
                    "HITLS_CFG_ProviderNewTLS13Config",
                    "HITLS_CFG_NewTLSConfig",
                    "HITLS_CFG_ProviderNewTLSConfig");

    private static final IDetectionRule<AstNode> TLS_CIPHER_SUITES =
            protocolRule(
                    new OpenHiTLSTlsConfigurationFactory(
                            1, OpenHiTLSTlsConfigurationFactory.Kind.CIPHER_SUITE),
                    "HITLS_CFG_SetCipherSuites",
                    "HITLS_SetCipherSuites");

    private static final IDetectionRule<AstNode> TLS_GROUPS =
            protocolRule(
                    new OpenHiTLSTlsConfigurationFactory(
                            1, OpenHiTLSTlsConfigurationFactory.Kind.TLS_GROUP),
                    "HITLS_CFG_SetGroups",
                    "HITLS_CFG_SetGroupList",
                    "HITLS_SetEcGroups",
                    "HITLS_SetGroupList");

    private static final IDetectionRule<AstNode> TLS_SIGNATURE_SCHEMES =
            protocolRule(
                    new OpenHiTLSTlsConfigurationFactory(
                            1, OpenHiTLSTlsConfigurationFactory.Kind.TLS_SIGNATURE_SCHEME),
                    "HITLS_CFG_SetSignature",
                    "HITLS_SetSigalgsList");

    private OpenHiTLSSsl() {
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
