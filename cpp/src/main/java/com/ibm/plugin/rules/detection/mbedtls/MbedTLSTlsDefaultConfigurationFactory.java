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

import com.ibm.engine.model.IAction;
import com.ibm.engine.model.factory.IActionFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import java.util.Set;
import javax.annotation.Nonnull;

/** Detects the default TLS preset selected by mbedtls_ssl_config_defaults. */
public final class MbedTLSTlsDefaultConfigurationFactory implements IActionFactory<AstNode> {

    private static final int PRESET_ARGUMENT_INDEX = 3;
    private static final String DEFAULT_PRESET = "MBEDTLS_SSL_PRESET_DEFAULT";

    @Nonnull
    @Override
    public Optional<IAction<AstNode>> apply(@Nonnull AstNode astNode) {
        Set<String> presetIdentifiers =
                MbedTLSAstUtils.getLogicalArgument(astNode, PRESET_ARGUMENT_INDEX)
                        .map(MbedTLSAstUtils::identifiers)
                        .orElse(Set.of());
        if (!presetIdentifiers.contains(DEFAULT_PRESET)) {
            return Optional.empty();
        }
        return Optional.of(
                new MbedTLSTlsConfigurationAction(
                        MbedTLSAlgorithmNames.DEFAULT_TLS_CIPHER_SUITES,
                        MbedTLSAlgorithmNames.DEFAULT_TLS_GROUPS,
                        MbedTLSAlgorithmNames.DEFAULT_TLS_SIGNATURE_SCHEMES,
                        MbedTLSAlgorithmNames.DEFAULT_TLS_VERSION,
                        false,
                        astNode));
    }
}
