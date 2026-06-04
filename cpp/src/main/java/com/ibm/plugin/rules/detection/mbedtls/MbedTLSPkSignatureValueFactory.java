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
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.factory.IActionFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;

public final class MbedTLSPkSignatureValueFactory implements IActionFactory<AstNode> {

    private static final Map<String, String> SIGNATURE_PREFIXES = signaturePrefixes();

    private final int signatureTypeArgumentIndex;
    private final int digestArgumentIndex;

    public MbedTLSPkSignatureValueFactory(int signatureTypeArgumentIndex, int digestArgumentIndex) {
        this.signatureTypeArgumentIndex = signatureTypeArgumentIndex;
        this.digestArgumentIndex = digestArgumentIndex;
    }

    @Nonnull
    @Override
    public Optional<IAction<AstNode>> apply(@Nonnull AstNode astNode) {
        Optional<String> signaturePrefix =
                MbedTLSAstUtils.getLogicalArgument(astNode, signatureTypeArgumentIndex)
                        .flatMap(
                                argument ->
                                        MbedTLSAstUtils.firstMappedIdentifier(
                                                argument, SIGNATURE_PREFIXES))
                        .map(SIGNATURE_PREFIXES::get);

        Optional<String> digestSuffix =
                MbedTLSAstUtils.getLogicalArgument(astNode, digestArgumentIndex)
                        .flatMap(
                                argument ->
                                        MbedTLSAstUtils.firstMappedIdentifier(
                                                argument, MbedTLSAlgorithmNames.HASH_SUFFIXES))
                        .flatMap(MbedTLSAlgorithmNames::hashSuffixFor);

        if (signaturePrefix.isPresent() && digestSuffix.isPresent()) {
            return Optional.of(
                    new ValueAction<>(signaturePrefix.get() + digestSuffix.get(), astNode));
        }
        return Optional.empty();
    }

    @Nonnull
    private static Map<String, String> signaturePrefixes() {
        Map<String, String> mappings = new LinkedHashMap<>();
        mappings.put("MBEDTLS_PK_SIGALG_RSA_PKCS1V15", "RSA-");
        mappings.put("MBEDTLS_PK_SIGALG_RSA_PSS", "RSA-PSS-");
        mappings.put("MBEDTLS_PK_SIGALG_ECDSA", "ECDSA-");
        return mappings;
    }
}
