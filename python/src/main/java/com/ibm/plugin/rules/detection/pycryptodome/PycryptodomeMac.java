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

import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.IDetectionRule.ParametersFactoryBuilder;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

public final class PycryptodomeMac {

    private PycryptodomeMac() {
        // utility
    }

    private static IDetectionRule<Tree> hmacRuleWithDigestAt(int digestParameterIndex) {
        ParametersFactoryBuilder<Tree> builder =
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes(Pycryptodome.types("Hash.HMAC"))
                        .forMethods("new")
                        .withMethodParameter(ANY);
        for (int i = 1; i < digestParameterIndex; i++) {
            builder = builder.withMethodParameter(ANY);
        }
        return builder.withMethodParameter(ANY)
                .shouldBeDetectedAs(new AlgorithmFactory<>())
                .buildForContext(new MacContext(Map.of("kind", "hmac")))
                .inBundle(() -> "PyCryptodome")
                .withoutDependingDetectionRules();
    }

    private static IDetectionRule<Tree> cmacRuleWithCipherAt(int cipherParameterIndex) {
        ParametersFactoryBuilder<Tree> builder =
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes(Pycryptodome.types("Hash.CMAC"))
                        .forMethods("new")
                        .withMethodParameter(ANY);
        for (int i = 1; i < cipherParameterIndex; i++) {
            builder = builder.withMethodParameter(ANY);
        }
        return builder.withMethodParameter(ANY)
                .shouldBeDetectedAs(new AlgorithmFactory<>())
                .buildForContext(new MacContext(Map.of("kind", "cmac")))
                .inBundle(() -> "PyCryptodome")
                .withoutDependingDetectionRules();
    }

    private static IDetectionRule<Tree> poly1305Rule() {
        return new DetectionRuleBuilder<Tree>()
                .createDetectionRule()
                .forObjectTypes(Pycryptodome.types("Hash.Poly1305"))
                .forMethods("new")
                .shouldBeDetectedAs(new ValueActionFactory<>("Poly1305"))
                .withAnyParameters()
                .buildForContext(new MacContext())
                .inBundle(() -> "PyCryptodome")
                .withoutDependingDetectionRules();
    }

    private static IDetectionRule<Tree> kmacRule(String module) {
        return new DetectionRuleBuilder<Tree>()
                .createDetectionRule()
                .forObjectTypes(Pycryptodome.types("Hash." + module))
                .forMethods("new")
                .shouldBeDetectedAs(new ValueActionFactory<>(module))
                .withAnyParameters()
                .buildForContext(new MacContext())
                .inBundle(() -> "PyCryptodome")
                .withoutDependingDetectionRules();
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(
                hmacRuleWithDigestAt(1),
                hmacRuleWithDigestAt(2),
                cmacRuleWithCipherAt(1),
                cmacRuleWithCipherAt(2),
                poly1305Rule(),
                kmacRule("KMAC128"),
                kmacRule("KMAC256"));
    }
}
