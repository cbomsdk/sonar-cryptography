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
package com.ibm.plugin.rules.detection.openhitls.mac;

import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.openhitls.OpenHiTLSAlgorithmNames;
import com.ibm.plugin.rules.detection.openhitls.OpenHiTLSArgumentValueFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/** Detection rules for openHiTLS EAL MAC APIs. */
public final class OpenHiTLSMac {

    private static final String BUNDLE = "openHiTLS";

    private static final IDetectionRule<AstNode> EAL_MAC = macRule(0, "CRYPT_EAL_MacNewCtx");

    private static final IDetectionRule<AstNode> EAL_PROVIDER_MAC =
            macRule(1, "CRYPT_EAL_ProviderMacNewCtx");

    private OpenHiTLSMac() {
        // private
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(EAL_MAC, EAL_PROVIDER_MAC);
    }

    @Nonnull
    private static IDetectionRule<AstNode> macRule(int argumentIndex, String... methods) {
        return new DetectionRuleBuilder<AstNode>()
                .createDetectionRule()
                .forObjectTypes("*")
                .forMethods(methods)
                .shouldBeDetectedAs(
                        new OpenHiTLSArgumentValueFactory(
                                argumentIndex, OpenHiTLSAlgorithmNames.MACS))
                .withAnyParameters()
                .buildForContext(new MacContext())
                .inBundle(() -> BUNDLE)
                .withoutDependingDetectionRules();
    }
}
