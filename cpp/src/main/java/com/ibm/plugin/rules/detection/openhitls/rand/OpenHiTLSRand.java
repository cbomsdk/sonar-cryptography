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
package com.ibm.plugin.rules.detection.openhitls.rand;

import com.ibm.engine.model.context.PRNGContext;
import com.ibm.engine.model.factory.IActionFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.openhitls.OpenHiTLSAlgorithmNames;
import com.ibm.plugin.rules.detection.openhitls.OpenHiTLSArgumentValueFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/** Detection rules for openHiTLS EAL random number generation APIs. */
public final class OpenHiTLSRand {

    private static final String BUNDLE = "openHiTLS";

    private static final IDetectionRule<AstNode> EAL_RAND_INIT =
            prngRule(
                    new OpenHiTLSArgumentValueFactory(0, OpenHiTLSAlgorithmNames.RANDS),
                    "CRYPT_EAL_RandInit");

    private static final IDetectionRule<AstNode> EAL_PROVIDER_RAND_INIT =
            prngRule(
                    new OpenHiTLSArgumentValueFactory(1, OpenHiTLSAlgorithmNames.RANDS),
                    "CRYPT_EAL_ProviderRandInitCtx",
                    "CRYPT_EAL_ProviderDrbgNewCtx");

    private static final IDetectionRule<AstNode> EAL_RAND_BYTES =
            prngRule(
                    new ValueActionFactory<>("RAND"),
                    "CRYPT_EAL_Randbytes",
                    "CRYPT_EAL_RandbytesEx",
                    "CRYPT_EAL_RandbytesWithAdin",
                    "CRYPT_EAL_RandbytesWithAdinEx");

    private OpenHiTLSRand() {
        // private
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(EAL_RAND_INIT, EAL_PROVIDER_RAND_INIT, EAL_RAND_BYTES);
    }

    @Nonnull
    private static IDetectionRule<AstNode> prngRule(
            @Nonnull IActionFactory<AstNode> factory, String... methods) {
        return new DetectionRuleBuilder<AstNode>()
                .createDetectionRule()
                .forObjectTypes("*")
                .forMethods(methods)
                .shouldBeDetectedAs(factory)
                .withAnyParameters()
                .buildForContext(new PRNGContext())
                .inBundle(() -> BUNDLE)
                .withoutDependingDetectionRules();
    }
}
