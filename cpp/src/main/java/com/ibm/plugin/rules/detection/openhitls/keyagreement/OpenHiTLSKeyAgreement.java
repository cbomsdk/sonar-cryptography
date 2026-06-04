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
package com.ibm.plugin.rules.detection.openhitls.keyagreement;

import com.ibm.engine.model.context.KeyAgreementContext;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.openhitls.OpenHiTLSAlgorithmNames;
import com.ibm.plugin.rules.detection.openhitls.OpenHiTLSArgumentValueFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/** Detection rules for openHiTLS EAL key agreement algorithms. */
public final class OpenHiTLSKeyAgreement {

    private static final String BUNDLE = "openHiTLS";

    private static final IDetectionRule<AstNode> EAL_PKEY =
            keyAgreementRule(0, "CRYPT_EAL_PkeyNewCtx");

    private static final IDetectionRule<AstNode> EAL_PROVIDER_PKEY =
            keyAgreementRule(1, "CRYPT_EAL_ProviderPkeyNewCtx");

    private OpenHiTLSKeyAgreement() {
        // private
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(EAL_PKEY, EAL_PROVIDER_PKEY);
    }

    @Nonnull
    private static IDetectionRule<AstNode> keyAgreementRule(int argumentIndex, String... methods) {
        return new DetectionRuleBuilder<AstNode>()
                .createDetectionRule()
                .forObjectTypes("*")
                .forMethods(methods)
                .shouldBeDetectedAs(
                        new OpenHiTLSArgumentValueFactory(
                                argumentIndex, OpenHiTLSAlgorithmNames.KEY_AGREEMENTS))
                .withAnyParameters()
                .buildForContext(new KeyAgreementContext())
                .inBundle(() -> BUNDLE)
                .withoutDependingDetectionRules();
    }
}
