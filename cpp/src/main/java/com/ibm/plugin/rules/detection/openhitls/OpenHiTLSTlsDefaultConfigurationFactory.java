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
package com.ibm.plugin.rules.detection.openhitls;

import com.ibm.engine.model.IAction;
import com.ibm.engine.model.factory.IActionFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.annotation.Nonnull;

/** Detects openHiTLS TLS configuration constructors that apply library defaults. */
public final class OpenHiTLSTlsDefaultConfigurationFactory implements IActionFactory<AstNode> {

    private static final Map<String, Preset> PRESETS =
            Map.of(
                    "HITLS_CFG_NewTLS12Config",
                    new Preset("1.2", OpenHiTLSAlgorithmNames.DEFAULT_TLS12_CIPHER_SUITES),
                    "HITLS_CFG_ProviderNewTLS12Config",
                    new Preset("1.2", OpenHiTLSAlgorithmNames.DEFAULT_TLS12_CIPHER_SUITES),
                    "HITLS_CFG_NewTLS13Config",
                    new Preset("1.3", OpenHiTLSAlgorithmNames.DEFAULT_TLS13_CIPHER_SUITES),
                    "HITLS_CFG_ProviderNewTLS13Config",
                    new Preset("1.3", OpenHiTLSAlgorithmNames.DEFAULT_TLS13_CIPHER_SUITES),
                    "HITLS_CFG_NewTLSConfig",
                    new Preset(null, OpenHiTLSAlgorithmNames.DEFAULT_TLS_CIPHER_SUITES),
                    "HITLS_CFG_ProviderNewTLSConfig",
                    new Preset(null, OpenHiTLSAlgorithmNames.DEFAULT_TLS_CIPHER_SUITES));

    @Nonnull
    @Override
    public Optional<IAction<AstNode>> apply(@Nonnull AstNode astNode) {
        Set<String> identifiers = OpenHiTLSAstUtils.identifiers(astNode);
        return PRESETS.entrySet().stream()
                .filter(entry -> identifiers.contains(entry.getKey()))
                .findFirst()
                .map(entry -> entry.getValue().toAction(astNode));
    }

    private record Preset(String tlsVersion, List<String> cipherSuites) {

        @Nonnull
        private OpenHiTLSTlsConfigurationAction toAction(@Nonnull AstNode astNode) {
            return new OpenHiTLSTlsConfigurationAction(
                    cipherSuites,
                    OpenHiTLSAlgorithmNames.DEFAULT_TLS_GROUPS,
                    OpenHiTLSAlgorithmNames.DEFAULT_TLS_SIGNATURE_SCHEMES,
                    tlsVersion,
                    false,
                    astNode);
        }
    }
}
