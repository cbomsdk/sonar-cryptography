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
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import javax.annotation.Nonnull;

public final class MbedTLSTlsConfigurationFactory implements IActionFactory<AstNode> {

    public enum Kind {
        CIPHER_SUITE,
        TLS_GROUP,
        TLS_SIGNATURE_SCHEME
    }

    private final int argumentIndex;
    @Nonnull private final Kind kind;

    public MbedTLSTlsConfigurationFactory(int argumentIndex, @Nonnull Kind kind) {
        this.argumentIndex = argumentIndex;
        this.kind = kind;
    }

    @Nonnull
    @Override
    public Optional<IAction<AstNode>> apply(@Nonnull AstNode astNode) {
        Function<String, Optional<String>> resolver = resolver();
        Set<String> identifiers =
                MbedTLSAstUtils.getLogicalArgument(astNode, argumentIndex)
                        .map(
                                argument ->
                                        MbedTLSAstUtils.identifiersIncludingReferencedInitializers(
                                                astNode, argument, resolver))
                        .orElse(Set.of());
        List<String> values =
                identifiers.stream().map(resolver).flatMap(Optional::stream).distinct().toList();
        if (values.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(action(values, astNode));
    }

    @Nonnull
    private Function<String, Optional<String>> resolver() {
        return switch (kind) {
            case CIPHER_SUITE -> MbedTLSAlgorithmNames::tlsCipherSuiteFor;
            case TLS_GROUP -> MbedTLSAlgorithmNames::tlsGroupFor;
            case TLS_SIGNATURE_SCHEME -> MbedTLSAlgorithmNames::tlsSignatureSchemeFor;
        };
    }

    @Nonnull
    private MbedTLSTlsConfigurationAction action(
            @Nonnull List<String> values, @Nonnull AstNode astNode) {
        return switch (kind) {
            case CIPHER_SUITE ->
                    new MbedTLSTlsConfigurationAction(values, List.of(), List.of(), astNode);
            case TLS_GROUP ->
                    new MbedTLSTlsConfigurationAction(List.of(), values, List.of(), astNode);
            case TLS_SIGNATURE_SCHEME ->
                    new MbedTLSTlsConfigurationAction(List.of(), List.of(), values, astNode);
        };
    }
}
