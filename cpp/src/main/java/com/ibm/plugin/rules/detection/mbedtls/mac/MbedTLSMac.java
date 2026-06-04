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
package com.ibm.plugin.rules.detection.mbedtls.mac;

import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.factory.IActionFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.mbedtls.MbedTLSAlgorithmNames;
import com.ibm.plugin.rules.detection.mbedtls.MbedTLSArgumentValueFactory;
import com.ibm.plugin.rules.detection.mbedtls.MbedTLSHashPrefixedValueFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/** Detection rules for PSA MAC algorithms used by mbedTLS 4.x. */
public final class MbedTLSMac {

    private static final String BUNDLE = "MbedTLS";

    private static final IDetectionRule<AstNode> PSA_HMAC =
            rule(new MbedTLSHashPrefixedValueFactory(0, "HMAC-"), "PSA_ALG_HMAC");

    private static final IDetectionRule<AstNode> PSA_MAC_COMPUTE =
            directRule(1, "psa_mac_compute", "psa_mac_verify");

    private static final IDetectionRule<AstNode> PSA_MAC_SETUP =
            directRule(2, "psa_mac_sign_setup", "psa_mac_verify_setup");

    private static final IDetectionRule<AstNode> MBEDTLS_MD_HMAC =
            rule(
                    new ValueActionFactory<>("HMAC"),
                    "mbedtls_md_hmac_starts",
                    "mbedtls_md_hmac_update",
                    "mbedtls_md_hmac_finish",
                    "mbedtls_md_hmac_reset");

    private MbedTLSMac() {
        // private
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(PSA_HMAC, PSA_MAC_COMPUTE, PSA_MAC_SETUP, MBEDTLS_MD_HMAC);
    }

    @Nonnull
    private static IDetectionRule<AstNode> directRule(int argumentIndex, String... methods) {
        return rule(
                new MbedTLSArgumentValueFactory(argumentIndex, MbedTLSAlgorithmNames.MACS),
                methods);
    }

    @Nonnull
    private static IDetectionRule<AstNode> rule(
            @Nonnull IActionFactory<AstNode> factory, String... methods) {
        return new DetectionRuleBuilder<AstNode>()
                .createDetectionRule()
                .forObjectTypes("*")
                .forMethods(methods)
                .shouldBeDetectedAs(factory)
                .withAnyParameters()
                .buildForContext(new MacContext())
                .inBundle(() -> BUNDLE)
                .withoutDependingDetectionRules();
    }
}
