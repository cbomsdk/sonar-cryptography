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
package com.ibm.plugin.rules.detection.mbedtls.signature;

import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.IActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.mbedtls.MbedTLSAlgorithmNames;
import com.ibm.plugin.rules.detection.mbedtls.MbedTLSArgumentValueFactory;
import com.ibm.plugin.rules.detection.mbedtls.MbedTLSHashPrefixedValueFactory;
import com.ibm.plugin.rules.detection.mbedtls.MbedTLSPkSignatureValueFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/** Detection rules for mbedTLS PK signatures and PSA signature algorithms. */
public final class MbedTLSSignature {

    private static final String BUNDLE = "MbedTLS";

    private static final IDetectionRule<AstNode> MBEDTLS_PK_SIGN_EXT =
            rule(
                    new MbedTLSPkSignatureValueFactory(0, 2),
                    "mbedtls_pk_sign_ext",
                    "mbedtls_pk_verify_ext");

    private static final IDetectionRule<AstNode> PSA_RSA_PSS =
            hashRule("RSA-PSS-", "PSA_ALG_RSA_PSS", "PSA_ALG_RSA_PSS_ANY_SALT");

    private static final IDetectionRule<AstNode> PSA_RSA_PKCS1V15 =
            hashRule("RSA-", "PSA_ALG_RSA_PKCS1V15_SIGN");

    private static final IDetectionRule<AstNode> PSA_ECDSA =
            hashRule("ECDSA-", "PSA_ALG_ECDSA", "PSA_ALG_DETERMINISTIC_ECDSA");

    private static final IDetectionRule<AstNode> PSA_SIGNATURE_BARE =
            directRule(
                    1,
                    "psa_sign_hash",
                    "psa_verify_hash",
                    "psa_sign_message",
                    "psa_verify_message");

    private static final IDetectionRule<AstNode> PSA_SIGNATURE_START_BARE =
            directRule(2, "psa_sign_hash_start", "psa_verify_hash_start");

    private MbedTLSSignature() {
        // private
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                MBEDTLS_PK_SIGN_EXT,
                PSA_RSA_PSS,
                PSA_RSA_PKCS1V15,
                PSA_ECDSA,
                PSA_SIGNATURE_BARE,
                PSA_SIGNATURE_START_BARE);
    }

    @Nonnull
    private static IDetectionRule<AstNode> hashRule(@Nonnull String prefix, String... methods) {
        return rule(new MbedTLSHashPrefixedValueFactory(0, prefix), methods);
    }

    @Nonnull
    private static IDetectionRule<AstNode> directRule(int argumentIndex, String... methods) {
        return rule(
                new MbedTLSArgumentValueFactory(argumentIndex, MbedTLSAlgorithmNames.SIGNATURES),
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
                .buildForContext(new SignatureContext())
                .inBundle(() -> BUNDLE)
                .withoutDependingDetectionRules();
    }
}
