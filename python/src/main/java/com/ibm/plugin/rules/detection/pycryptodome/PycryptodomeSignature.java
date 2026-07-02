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

import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

public final class PycryptodomeSignature {

    private PycryptodomeSignature() {
        // utility
    }

    private static IDetectionRule<Tree> newRsaSignature(String module, boolean pss) {
        return new DetectionRuleBuilder<Tree>()
                .createDetectionRule()
                .forObjectTypes(Pycryptodome.types("Signature." + module))
                .forMethods("new")
                .withMethodParameter(ANY)
                .shouldBeDetectedAs(new AlgorithmFactory<Tree>("RSA"))
                .buildForContext(
                        pss ? new SignatureContext(Map.of("kind", "PSS")) : new SignatureContext())
                .inBundle(() -> "PyCryptodome")
                .withoutDependingDetectionRules();
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(newRsaSignature("pkcs1_15", false), newRsaSignature("pss", true));
    }
}
