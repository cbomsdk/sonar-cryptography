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
package com.ibm.plugin.rules.detection.hash;

import static com.ibm.engine.detection.MethodMatcher.ANY;

import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.AssignmentStatement;
import org.sonar.plugins.python.api.tree.CallExpression;
import org.sonar.plugins.python.api.tree.ExpressionStatement;
import org.sonar.plugins.python.api.tree.Name;
import org.sonar.plugins.python.api.tree.QualifiedExpression;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class PycaHash {

    private PycaHash() {
        // private
    }

    @SuppressWarnings("java:S2386")
    public static final List<String> hashes =
            Arrays.asList(
                    "SHA1",
                    "SHA512_224",
                    "SHA512_256",
                    "SHA224",
                    "SHA256",
                    "SHA384",
                    "SHA512",
                    "SHA3_224",
                    "SHA3_256",
                    "SHA3_384",
                    "SHA3_512",
                    "SHAKE128",
                    "SHAKE256",
                    "MD5",
                    "BLAKE2b",
                    "BLAKE2s",
                    "SM3");

    private static final List<List<String>> HASHLIB_HASHES =
            List.of(
                    List.of("sha1", "SHA1"),
                    List.of("sha224", "SHA224"),
                    List.of("sha256", "SHA256"),
                    List.of("sha384", "SHA384"),
                    List.of("sha512", "SHA512"),
                    List.of("sha3_224", "SHA3_224"),
                    List.of("sha3_256", "SHA3_256"),
                    List.of("sha3_384", "SHA3_384"),
                    List.of("sha3_512", "SHA3_512"),
                    List.of("shake_128", "SHAKE128"),
                    List.of("shake_256", "SHAKE256"),
                    List.of("md5", "MD5"),
                    List.of("blake2b", "BLAKE2b"),
                    List.of("blake2s", "BLAKE2s"));

    private static @Nonnull List<IDetectionRule<Tree>> hashesRules() {
        LinkedList<IDetectionRule<Tree>> rules = new LinkedList<>();
        for (final String hash : PycaHash.hashes) {
            rules.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("cryptography.hazmat.primitives.hashes")
                            .forMethods(hash)
                            .shouldBeDetectedAs(new ValueActionFactory<>(hash))
                            .withAnyParameters()
                            .buildForContext(new DigestContext())
                            .inBundle(() -> "Pyca")
                            .withoutDependingDetectionRules());
        }
        return rules;
    }

    private static @Nonnull List<IDetectionRule<Tree>> hashlibHashRules() {
        LinkedList<IDetectionRule<Tree>> rules = new LinkedList<>();
        for (final List<String> hash : HASHLIB_HASHES) {
            rules.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("hashlib")
                            .forMethods(hash.get(0))
                            .shouldBeDetectedAs(new ValueActionFactory<>(hash.get(1)))
                            .withAnyParameters()
                            .buildForContext(new DigestContext())
                            .inBundle(() -> "Hashlib")
                            .withoutDependingDetectionRules());
        }
        return rules;
    }

    private static @Nonnull List<IDetectionRule<Tree>> hashlibNewRules() {
        return List.of(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("hashlib")
                        .forMethods("new")
                        .withMethodParameter(ANY)
                        .shouldBeDetectedAs(new AlgorithmFactory<>())
                        .buildForContext(new DigestContext())
                        .inBundle(() -> "Hashlib")
                        .withoutDependingDetectionRules(),
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("hashlib")
                        .forMethods("new")
                        .withMethodParameter(ANY)
                        .shouldBeDetectedAs(new AlgorithmFactory<>())
                        .withMethodParameter(ANY)
                        .buildForContext(new DigestContext())
                        .inBundle(() -> "Hashlib")
                        .withoutDependingDetectionRules(),
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("hashlib")
                        .forMethods("new")
                        .withMethodParameter(ANY)
                        .shouldBeDetectedAs(new AlgorithmFactory<>())
                        .withMethodParameter(ANY)
                        .withMethodParameter(ANY)
                        .buildForContext(new DigestContext())
                        .inBundle(() -> "Hashlib")
                        .withoutDependingDetectionRules());
    }

    private static final List<IDetectionRule<Tree>> TOP_LEVEL_HASH_RULES =
            Stream.of(
                            hashesRules().stream(),
                            hashlibHashRules().stream(),
                            hashlibNewRules().stream())
                    .flatMap(i -> i)
                    .toList();

    private static final IDetectionRule<Tree> PRE_HASH =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("cryptography.hazmat.primitives.asymmetric.utils")
                    .forMethods("Prehashed")
                    .withMethodParameter("cryptography.hazmat.primitives.hashes.*")
                    .addDependingDetectionRules(hashesRules())
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        final List<IDetectionRule<Tree>> hashAndPrehashRules =
                new LinkedList<>(TOP_LEVEL_HASH_RULES);
        hashAndPrehashRules.add(PRE_HASH);
        return hashAndPrehashRules;
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> topLevelRules() {
        return new LinkedList<>(TOP_LEVEL_HASH_RULES);
    }

    public static boolean isTopLevelHashRule(@Nonnull IDetectionRule<Tree> rule) {
        return TOP_LEVEL_HASH_RULES.contains(rule);
    }

    public static boolean shouldScanAsRoot(@Nonnull Tree tree) {
        if (isDirectAssignmentValue(tree) || isDirectExpressionStatement(tree)) {
            return true;
        }

        Tree parent = tree.parent();
        while (parent != null) {
            if (parent instanceof CallExpression callExpression) {
                return callName(callExpression).map("Hash"::equals).orElse(false);
            }
            if (parent instanceof AssignmentStatement || parent instanceof ExpressionStatement) {
                return false;
            }
            parent = parent.parent();
        }
        return false;
    }

    private static boolean isDirectAssignmentValue(@Nonnull Tree tree) {
        return tree.parent() instanceof AssignmentStatement assignmentStatement
                && assignmentStatement.assignedValue() == tree;
    }

    private static boolean isDirectExpressionStatement(@Nonnull Tree tree) {
        return tree.parent() instanceof ExpressionStatement expressionStatement
                && expressionStatement.expressions().contains(tree);
    }

    private static Optional<String> callName(@Nonnull CallExpression callExpression) {
        if (callExpression.calleeSymbol() != null) {
            return Optional.of(callExpression.calleeSymbol().name());
        } else if (callExpression.callee() instanceof QualifiedExpression qualifiedExpression) {
            return Optional.of(qualifiedExpression.name().name());
        } else if (callExpression.callee() instanceof Name name) {
            return Optional.of(name.name());
        }
        return Optional.empty();
    }
}
