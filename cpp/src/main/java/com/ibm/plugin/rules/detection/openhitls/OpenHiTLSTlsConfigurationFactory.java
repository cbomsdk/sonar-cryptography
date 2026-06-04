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
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

public final class OpenHiTLSTlsConfigurationFactory implements IActionFactory<AstNode> {

    public enum Kind {
        CIPHER_SUITE,
        TLS_GROUP,
        TLS_SIGNATURE_SCHEME
    }

    private final int argumentIndex;
    @Nonnull private final Kind kind;

    public OpenHiTLSTlsConfigurationFactory(int argumentIndex, @Nonnull Kind kind) {
        this.argumentIndex = argumentIndex;
        this.kind = kind;
    }

    @Nonnull
    @Override
    public Optional<IAction<AstNode>> apply(@Nonnull AstNode astNode) {
        Optional<AstNode> argument = OpenHiTLSAstUtils.getLogicalArgument(astNode, argumentIndex);
        if (argument.isEmpty()) {
            return Optional.empty();
        }

        Function<String, Optional<String>> resolver = resolver();
        Set<String> identifiers =
                OpenHiTLSAstUtils.identifiersIncludingReferencedInitializers(
                        astNode, argument.get(), resolver);
        Stream<String> stringGroups =
                kind == Kind.TLS_GROUP
                        ? OpenHiTLSAstUtils.stringLiteralsIncludingReferencedInitializers(
                                        astNode, argument.get())
                                .stream()
                                .flatMap(OpenHiTLSAlgorithmNames::tlsGroupsFromGroupList)
                        : Stream.empty();
        List<String> values =
                Stream.concat(
                                identifiers.stream().map(resolver).flatMap(Optional::stream),
                                stringGroups)
                        .distinct()
                        .toList();
        if (values.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(action(values, astNode));
    }

    @Nonnull
    private Function<String, Optional<String>> resolver() {
        return switch (kind) {
            case CIPHER_SUITE -> OpenHiTLSAlgorithmNames::tlsCipherSuiteFor;
            case TLS_GROUP -> OpenHiTLSAlgorithmNames::tlsGroupFor;
            case TLS_SIGNATURE_SCHEME -> OpenHiTLSAlgorithmNames::tlsSignatureSchemeFor;
        };
    }

    @Nonnull
    private OpenHiTLSTlsConfigurationAction action(
            @Nonnull List<String> values, @Nonnull AstNode astNode) {
        return switch (kind) {
            case CIPHER_SUITE ->
                    new OpenHiTLSTlsConfigurationAction(values, List.of(), List.of(), astNode);
            case TLS_GROUP ->
                    new OpenHiTLSTlsConfigurationAction(List.of(), values, List.of(), astNode);
            case TLS_SIGNATURE_SCHEME ->
                    new OpenHiTLSTlsConfigurationAction(List.of(), List.of(), values, astNode);
        };
    }
}
