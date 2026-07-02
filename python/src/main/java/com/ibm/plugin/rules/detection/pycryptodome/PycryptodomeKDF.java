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

import com.ibm.engine.model.AlgorithmParameter;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.AlgorithmParameterFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.IDetectionRule.ParametersDependingRulesBuilder;
import com.ibm.engine.rule.IDetectionRule.PositionBuilder;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

public final class PycryptodomeKDF {

    private PycryptodomeKDF() {
        // utility
    }

    private static ParametersDependingRulesBuilder<Tree> pbkdf2Base(int hashParameterIndex) {
        return new DetectionRuleBuilder<Tree>()
                .createDetectionRule()
                .forObjectTypes(Pycryptodome.types("Protocol.KDF"))
                .forMethods("PBKDF2")
                .withMethodParameter(ANY)
                .withMethodParameter(ANY)
                .withMethodParameter("int")
                .shouldBeDetectedAs(new KeySizeFactory<Tree>(Size.UnitType.BYTE))
                .asChildOfParameterWithId(hashParameterIndex)
                .withMethodParameter("int")
                .shouldBeDetectedAs(
                        new AlgorithmParameterFactory<Tree>(AlgorithmParameter.Kind.ITERATIONS))
                .asChildOfParameterWithId(hashParameterIndex);
    }

    private static IDetectionRule<Tree> pbkdf2WithHashAt(int hashParameterIndex) {
        ParametersDependingRulesBuilder<Tree> builder = pbkdf2Base(hashParameterIndex);
        if (hashParameterIndex == 5) {
            return builder.withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new KeyDerivationFunctionContext(Map.of("kind", "pbkdf2")))
                    .inBundle(() -> "PyCryptodome")
                    .withoutDependingDetectionRules();
        }
        return builder.withMethodParameter(ANY)
                .shouldBeDetectedAs(new AlgorithmFactory<>())
                .buildForContext(new KeyDerivationFunctionContext(Map.of("kind", "pbkdf2")))
                .inBundle(() -> "PyCryptodome")
                .withoutDependingDetectionRules();
    }

    private static PositionBuilder<Tree> hkdfBase() {
        return new DetectionRuleBuilder<Tree>()
                .createDetectionRule()
                .forObjectTypes(Pycryptodome.types("Protocol.KDF"))
                .forMethods("HKDF")
                .withMethodParameter(ANY)
                .withMethodParameter("int")
                .shouldBeDetectedAs(new KeySizeFactory<Tree>(Size.UnitType.BYTE))
                .asChildOfParameterWithId(3)
                .withMethodParameter(ANY)
                .withMethodParameter(ANY)
                .shouldBeDetectedAs(new AlgorithmFactory<>());
    }

    private static IDetectionRule<Tree> hkdfWithArguments(int numberOfArguments) {
        PositionBuilder<Tree> builder = hkdfBase();
        return switch (numberOfArguments) {
            case 4 ->
                    builder.buildForContext(
                                    new KeyDerivationFunctionContext(Map.of("kind", "hkdf")))
                            .inBundle(() -> "PyCryptodome")
                            .withoutDependingDetectionRules();
            case 5 ->
                    builder.withMethodParameter(ANY)
                            .buildForContext(
                                    new KeyDerivationFunctionContext(Map.of("kind", "hkdf")))
                            .inBundle(() -> "PyCryptodome")
                            .withoutDependingDetectionRules();
            case 6 ->
                    builder.withMethodParameter(ANY)
                            .withMethodParameter(ANY)
                            .buildForContext(
                                    new KeyDerivationFunctionContext(Map.of("kind", "hkdf")))
                            .inBundle(() -> "PyCryptodome")
                            .withoutDependingDetectionRules();
            default -> throw new IllegalArgumentException("Unsupported HKDF argument count");
        };
    }

    private static ParametersDependingRulesBuilder<Tree> scryptBase() {
        return new DetectionRuleBuilder<Tree>()
                .createDetectionRule()
                .forObjectTypes(Pycryptodome.types("Protocol.KDF"))
                .forMethods("scrypt")
                .shouldBeDetectedAs(new ValueActionFactory<>("Scrypt"))
                .withMethodParameter(ANY)
                .withMethodParameter(ANY)
                .withMethodParameter("int")
                .shouldBeDetectedAs(new KeySizeFactory<Tree>(Size.UnitType.BYTE))
                .asChildOfParameterWithId(0);
    }

    private static IDetectionRule<Tree> scryptWithArguments(int numberOfArguments) {
        ParametersDependingRulesBuilder<Tree> builder = scryptBase();
        return switch (numberOfArguments) {
            case 6 ->
                    builder.withMethodParameter(ANY)
                            .withMethodParameter(ANY)
                            .withMethodParameter(ANY)
                            .buildForContext(new KeyDerivationFunctionContext())
                            .inBundle(() -> "PyCryptodome")
                            .withoutDependingDetectionRules();
            case 7 ->
                    builder.withMethodParameter(ANY)
                            .withMethodParameter(ANY)
                            .withMethodParameter(ANY)
                            .withMethodParameter(ANY)
                            .buildForContext(new KeyDerivationFunctionContext())
                            .inBundle(() -> "PyCryptodome")
                            .withoutDependingDetectionRules();
            default -> throw new IllegalArgumentException("Unsupported scrypt argument count");
        };
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(
                pbkdf2WithHashAt(4),
                pbkdf2WithHashAt(5),
                hkdfWithArguments(4),
                hkdfWithArguments(5),
                hkdfWithArguments(6),
                scryptWithArguments(6),
                scryptWithArguments(7));
    }
}
