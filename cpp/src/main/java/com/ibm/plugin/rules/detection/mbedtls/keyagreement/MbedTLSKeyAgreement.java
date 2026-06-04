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
package com.ibm.plugin.rules.detection.mbedtls.keyagreement;

import com.ibm.engine.model.context.KeyAgreementContext;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.mbedtls.MbedTLSAlgorithmNames;
import com.ibm.plugin.rules.detection.mbedtls.MbedTLSArgumentValueFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/** Detection rules for PSA raw key agreement algorithms used by mbedTLS. */
public final class MbedTLSKeyAgreement {

    private static final String BUNDLE = "MbedTLS";

    private static final IDetectionRule<AstNode> PSA_RAW_KEY_AGREEMENT =
            keyAgreementRule(0, "psa_raw_key_agreement", "PSA_ALG_KEY_AGREEMENT");

    private MbedTLSKeyAgreement() {
        // private
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(PSA_RAW_KEY_AGREEMENT);
    }

    @Nonnull
    private static IDetectionRule<AstNode> keyAgreementRule(int argumentIndex, String... methods) {
        return new DetectionRuleBuilder<AstNode>()
                .createDetectionRule()
                .forObjectTypes("*")
                .forMethods(methods)
                .shouldBeDetectedAs(
                        new MbedTLSArgumentValueFactory(
                                argumentIndex, MbedTLSAlgorithmNames.KEY_AGREEMENTS))
                .withAnyParameters()
                .buildForContext(new KeyAgreementContext())
                .inBundle(() -> BUNDLE)
                .withoutDependingDetectionRules();
    }
}
