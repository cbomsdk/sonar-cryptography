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
package com.ibm.plugin.rules.detection.pycryptodome;

import static com.ibm.engine.detection.MethodMatcher.ANY;

import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.CipherActionFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.IDetectionRule.ParametersDependingRulesBuilder;
import com.ibm.engine.rule.IDetectionRule.ParametersFactoryBuilder;
import com.ibm.engine.rule.IDetectionRule.ParametersFinalDetectionRuleBuilder;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

public final class PycryptodomeCipher {
    private static final int MAX_NEW_ARGUMENTS = 7;

    private static final List<CipherModule> CIPHERS =
            List.of(
                    new CipherModule("AES", "AES", true),
                    new CipherModule("DES", "DES", true),
                    new CipherModule("DES3", "TripleDES", true),
                    new CipherModule("ARC2", "RC2", true),
                    new CipherModule("Blowfish", "Blowfish", true),
                    new CipherModule("CAST", "CAST5", true),
                    new CipherModule("ChaCha20", "ChaCha20", false),
                    new CipherModule("Salsa20", "Salsa20", false),
                    new CipherModule("ARC4", "ARC4", false),
                    new CipherModule("PKCS1_OAEP", "RSA", false),
                    new CipherModule("PKCS1_v1_5", "RSA", false));

    private PycryptodomeCipher() {
        // utility
    }

    private static IDetectionRule<Tree> encryptRule() {
        return new DetectionRuleBuilder<Tree>()
                .createDetectionRule()
                .forObjectTypes(Pycryptodome.types("Cipher.*"))
                .forMethods("encrypt", "encrypt_and_digest")
                .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                .withAnyParameters()
                .buildForContext(new CipherContext())
                .inBundle(() -> "PyCryptodome")
                .withoutDependingDetectionRules();
    }

    private static IDetectionRule<Tree> decryptRule() {
        return new DetectionRuleBuilder<Tree>()
                .createDetectionRule()
                .forObjectTypes(Pycryptodome.types("Cipher.*"))
                .forMethods("decrypt", "decrypt_and_verify")
                .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                .withAnyParameters()
                .buildForContext(new CipherContext())
                .inBundle(() -> "PyCryptodome")
                .withoutDependingDetectionRules();
    }

    private static @Nonnull List<IDetectionRule<Tree>> followCipherObjectRules() {
        return List.of(encryptRule(), decryptRule());
    }

    private static IDetectionRule<Tree> newCipherRule(
            CipherModule cipherModule, int numberOfArguments) {
        ParametersFactoryBuilder<Tree> builder =
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes(Pycryptodome.types("Cipher." + cipherModule.module()))
                        .forMethods("new")
                        .shouldBeDetectedAs(new ValueActionFactory<>(cipherModule.algorithm()))
                        .withMethodParameter(ANY);

        if (cipherModule.hasMode()) {
            ParametersDependingRulesBuilder<Tree> withMode =
                    builder.withMethodParameter(ANY)
                            .shouldBeDetectedAs(new PycryptodomeModeFactory())
                            .asChildOfParameterWithId(-1);
            return buildWithExtraArguments(withMode, numberOfArguments - 2);
        }

        return buildWithExtraArguments(builder, numberOfArguments - 1);
    }

    private static IDetectionRule<Tree> buildWithExtraArguments(
            ParametersFinalDetectionRuleBuilder<Tree> builder, int extraArguments) {
        return switch (extraArguments) {
            case 0 -> finish(builder);
            case 1 -> finish(builder.withMethodParameter(ANY));
            case 2 -> finish(builder.withMethodParameter(ANY).withMethodParameter(ANY));
            case 3 ->
                    finish(
                            builder.withMethodParameter(ANY)
                                    .withMethodParameter(ANY)
                                    .withMethodParameter(ANY));
            case 4 ->
                    finish(
                            builder.withMethodParameter(ANY)
                                    .withMethodParameter(ANY)
                                    .withMethodParameter(ANY)
                                    .withMethodParameter(ANY));
            case 5 ->
                    finish(
                            builder.withMethodParameter(ANY)
                                    .withMethodParameter(ANY)
                                    .withMethodParameter(ANY)
                                    .withMethodParameter(ANY)
                                    .withMethodParameter(ANY));
            case 6 ->
                    finish(
                            builder.withMethodParameter(ANY)
                                    .withMethodParameter(ANY)
                                    .withMethodParameter(ANY)
                                    .withMethodParameter(ANY)
                                    .withMethodParameter(ANY)
                                    .withMethodParameter(ANY));
            default -> throw new IllegalArgumentException("Unsupported argument count");
        };
    }

    private static IDetectionRule<Tree> buildWithExtraArguments(
            ParametersDependingRulesBuilder<Tree> builder, int extraArguments) {
        return switch (extraArguments) {
            case 0 -> finish(builder);
            case 1 -> finish(builder.withMethodParameter(ANY));
            case 2 -> finish(builder.withMethodParameter(ANY).withMethodParameter(ANY));
            case 3 ->
                    finish(
                            builder.withMethodParameter(ANY)
                                    .withMethodParameter(ANY)
                                    .withMethodParameter(ANY));
            case 4 ->
                    finish(
                            builder.withMethodParameter(ANY)
                                    .withMethodParameter(ANY)
                                    .withMethodParameter(ANY)
                                    .withMethodParameter(ANY));
            case 5 ->
                    finish(
                            builder.withMethodParameter(ANY)
                                    .withMethodParameter(ANY)
                                    .withMethodParameter(ANY)
                                    .withMethodParameter(ANY)
                                    .withMethodParameter(ANY));
            default -> throw new IllegalArgumentException("Unsupported argument count");
        };
    }

    private static IDetectionRule<Tree> buildWithExtraArguments(
            ParametersFactoryBuilder<Tree> builder, int extraArguments) {
        return switch (extraArguments) {
            case 0 -> finish(builder);
            case 1 -> finish(builder.withMethodParameter(ANY));
            case 2 -> finish(builder.withMethodParameter(ANY).withMethodParameter(ANY));
            case 3 ->
                    finish(
                            builder.withMethodParameter(ANY)
                                    .withMethodParameter(ANY)
                                    .withMethodParameter(ANY));
            case 4 ->
                    finish(
                            builder.withMethodParameter(ANY)
                                    .withMethodParameter(ANY)
                                    .withMethodParameter(ANY)
                                    .withMethodParameter(ANY));
            case 5 ->
                    finish(
                            builder.withMethodParameter(ANY)
                                    .withMethodParameter(ANY)
                                    .withMethodParameter(ANY)
                                    .withMethodParameter(ANY)
                                    .withMethodParameter(ANY));
            case 6 ->
                    finish(
                            builder.withMethodParameter(ANY)
                                    .withMethodParameter(ANY)
                                    .withMethodParameter(ANY)
                                    .withMethodParameter(ANY)
                                    .withMethodParameter(ANY)
                                    .withMethodParameter(ANY));
            default -> throw new IllegalArgumentException("Unsupported argument count");
        };
    }

    private static IDetectionRule<Tree> finish(ParametersFinalDetectionRuleBuilder<Tree> builder) {
        return builder.buildForContext(new CipherContext(Map.of("kind", "algorithm")))
                .inBundle(() -> "PyCryptodome")
                .withDependingDetectionRules(followCipherObjectRules());
    }

    private static IDetectionRule<Tree> finish(ParametersDependingRulesBuilder<Tree> builder) {
        return builder.buildForContext(new CipherContext(Map.of("kind", "algorithm")))
                .inBundle(() -> "PyCryptodome")
                .withDependingDetectionRules(followCipherObjectRules());
    }

    private static IDetectionRule<Tree> finish(ParametersFactoryBuilder<Tree> builder) {
        return builder.buildForContext(new CipherContext(Map.of("kind", "algorithm")))
                .inBundle(() -> "PyCryptodome")
                .withDependingDetectionRules(followCipherObjectRules());
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        List<IDetectionRule<Tree>> rules = new LinkedList<>();
        for (CipherModule cipher : CIPHERS) {
            int start = cipher.hasMode() ? 2 : 1;
            for (int args = start; args <= MAX_NEW_ARGUMENTS; args++) {
                rules.add(newCipherRule(cipher, args));
            }
        }
        return rules;
    }

    private record CipherModule(String module, String algorithm, boolean hasMode) {}
}
