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

import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.factory.CurveFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.IDetectionRule.PositionBuilder;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

public final class PycryptodomePublicKey {

    private PycryptodomePublicKey() {
        // utility
    }

    private static PositionBuilder<Tree> generateSizedKeyBase(String module) {
        return new DetectionRuleBuilder<Tree>()
                .createDetectionRule()
                .forObjectTypes(Pycryptodome.types("PublicKey." + module))
                .forMethods("generate")
                .withMethodParameter("int")
                .shouldBeDetectedAs(new KeySizeFactory<Tree>(Size.UnitType.BIT));
    }

    private static IDetectionRule<Tree> generateSizedKey(
            String module, String algorithm, int numberOfArguments) {
        PositionBuilder<Tree> builder = generateSizedKeyBase(module);
        return switch (numberOfArguments) {
            case 1 ->
                    builder.buildForContext(new PrivateKeyContext(Map.of("algorithm", algorithm)))
                            .inBundle(() -> "PyCryptodome")
                            .withoutDependingDetectionRules();
            case 2 ->
                    builder.withMethodParameter(ANY)
                            .buildForContext(new PrivateKeyContext(Map.of("algorithm", algorithm)))
                            .inBundle(() -> "PyCryptodome")
                            .withoutDependingDetectionRules();
            case 3 ->
                    builder.withMethodParameter(ANY)
                            .withMethodParameter(ANY)
                            .buildForContext(new PrivateKeyContext(Map.of("algorithm", algorithm)))
                            .inBundle(() -> "PyCryptodome")
                            .withoutDependingDetectionRules();
            default -> throw new IllegalArgumentException("Unsupported key argument count");
        };
    }

    private static PositionBuilder<Tree> generateEcKeyBase() {
        return new DetectionRuleBuilder<Tree>()
                .createDetectionRule()
                .forObjectTypes(Pycryptodome.types("PublicKey.ECC"))
                .forMethods("generate")
                .withMethodParameter(ANY)
                .shouldBeDetectedAs(new CurveFactory<>());
    }

    private static IDetectionRule<Tree> generateEcKey(int numberOfArguments) {
        PositionBuilder<Tree> builder = generateEcKeyBase();
        return switch (numberOfArguments) {
            case 1 ->
                    builder.buildForContext(new PrivateKeyContext(Map.of("algorithm", "EC")))
                            .inBundle(() -> "PyCryptodome")
                            .withoutDependingDetectionRules();
            case 2 ->
                    builder.withMethodParameter(ANY)
                            .buildForContext(new PrivateKeyContext(Map.of("algorithm", "EC")))
                            .inBundle(() -> "PyCryptodome")
                            .withoutDependingDetectionRules();
            default -> throw new IllegalArgumentException("Unsupported ECC argument count");
        };
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        List<IDetectionRule<Tree>> rules = new LinkedList<>();
        for (int args = 1; args <= 3; args++) {
            rules.add(generateSizedKey("RSA", "RSA", args));
            rules.add(generateSizedKey("DSA", "DSA", args));
        }
        for (int args = 1; args <= 2; args++) {
            rules.add(generateEcKey(args));
        }
        return rules;
    }
}
