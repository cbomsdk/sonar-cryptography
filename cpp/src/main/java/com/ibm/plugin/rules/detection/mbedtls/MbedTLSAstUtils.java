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

import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.GenericTokenType;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import javax.annotation.Nonnull;
import org.sonar.cxx.parser.CxxGrammarImpl;
import org.sonar.cxx.utils.CxxAstNodeHelper;

final class MbedTLSAstUtils {

    private MbedTLSAstUtils() {
        // utility class
    }

    @Nonnull
    static Optional<AstNode> getLogicalArgument(
            @Nonnull AstNode methodCallNode, int argumentIndex) {
        List<AstNode> arguments = CxxAstNodeHelper.getFunctionCallArguments(methodCallNode);
        if (arguments.isEmpty()) {
            return Optional.empty();
        }

        List<AstNode> logicalArguments = splitCommaSeparated(arguments);
        if (logicalArguments.size() == 1) {
            logicalArguments = splitCommaSeparated(logicalArguments.get(0).getChildren());
        }

        if (argumentIndex < logicalArguments.size()) {
            return Optional.of(logicalArguments.get(argumentIndex));
        }
        return Optional.empty();
    }

    @Nonnull
    static Optional<String> firstMappedIdentifier(
            @Nonnull AstNode node, @Nonnull Map<String, String> mappings) {
        Set<String> identifiers = identifiers(node);
        return mappings.keySet().stream().filter(identifiers::contains).findFirst();
    }

    @Nonnull
    static Set<String> identifiers(@Nonnull AstNode node) {
        Set<String> identifiers = new LinkedHashSet<>();
        collectIdentifiers(node, identifiers);
        return identifiers;
    }

    @Nonnull
    static Set<String> identifiersIncludingReferencedInitializers(
            @Nonnull AstNode callNode,
            @Nonnull AstNode argumentNode,
            @Nonnull Function<String, Optional<String>> resolver) {
        Set<String> identifiers = identifiers(argumentNode);
        Set<String> expandedIdentifiers = new LinkedHashSet<>(identifiers);
        identifiers.stream()
                .filter(identifier -> resolver.apply(identifier).isEmpty())
                .map(identifier -> findReferencedInitializer(callNode, identifier))
                .flatMap(Optional::stream)
                .map(MbedTLSAstUtils::identifiers)
                .forEach(expandedIdentifiers::addAll);
        return expandedIdentifiers;
    }

    private static void collectIdentifiers(
            @Nonnull AstNode node, @Nonnull Set<String> identifiers) {
        if (node.is(GenericTokenType.IDENTIFIER)) {
            identifiers.add(node.getTokenValue());
        }
        node.getChildren().forEach(child -> collectIdentifiers(child, identifiers));
    }

    @Nonnull
    private static Optional<AstNode> findReferencedInitializer(
            @Nonnull AstNode callNode, @Nonnull String identifier) {
        Optional<AstNode> callFunction = firstAncestor(callNode, CxxGrammarImpl.functionDefinition);
        List<AstNode> declarations =
                root(callNode).getDescendants(CxxGrammarImpl.initDeclarator).stream()
                        .filter(declaration -> isVisibleFrom(declaration, callNode, callFunction))
                        .filter(declaration -> declaresIdentifier(declaration, identifier))
                        .sorted(
                                (left, right) ->
                                        Integer.compare(right.getFromIndex(), left.getFromIndex()))
                        .toList();
        if (declarations.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(declarations.get(0));
    }

    private static boolean isVisibleFrom(
            @Nonnull AstNode declaration,
            @Nonnull AstNode callNode,
            @Nonnull Optional<AstNode> callFunction) {
        if (declaration.getFromIndex() >= callNode.getFromIndex()
                || declaration.getTokenLine() > callNode.getTokenLine()) {
            return false;
        }
        Optional<AstNode> declarationFunction =
                firstAncestor(declaration, CxxGrammarImpl.functionDefinition);
        return declarationFunction.isEmpty()
                || (callFunction.isPresent() && declarationFunction.get() == callFunction.get());
    }

    private static boolean declaresIdentifier(
            @Nonnull AstNode declaration, @Nonnull String identifier) {
        return declaration.getDescendants(GenericTokenType.IDENTIFIER).stream()
                .findFirst()
                .map(AstNode::getTokenValue)
                .filter(identifier::equals)
                .isPresent();
    }

    @Nonnull
    private static Optional<AstNode> firstAncestor(
            @Nonnull AstNode node, @Nonnull CxxGrammarImpl type) {
        AstNode parent = node.getParent();
        while (parent != null) {
            if (parent.is(type)) {
                return Optional.of(parent);
            }
            parent = parent.getParent();
        }
        return Optional.empty();
    }

    @Nonnull
    private static AstNode root(@Nonnull AstNode node) {
        AstNode current = node;
        while (current.getParent() != null) {
            current = current.getParent();
        }
        return current;
    }

    @Nonnull
    private static List<AstNode> splitCommaSeparated(@Nonnull List<AstNode> nodes) {
        if (nodes.isEmpty()) {
            return List.of();
        }

        boolean hasComma = nodes.stream().anyMatch(node -> ",".equals(node.getTokenValue()));
        if (!hasComma) {
            return nodes;
        }

        List<AstNode> arguments = new ArrayList<>();
        for (int i = 0; i < nodes.size(); i++) {
            AstNode node = nodes.get(i);
            if (",".equals(node.getTokenValue())) {
                continue;
            }
            arguments.add(node);
        }
        return arguments;
    }
}
