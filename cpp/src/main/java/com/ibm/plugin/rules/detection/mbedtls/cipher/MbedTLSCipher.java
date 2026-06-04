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
package com.ibm.plugin.rules.detection.mbedtls.cipher;

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.mbedtls.MbedTLSAlgorithmNames;
import com.ibm.plugin.rules.detection.mbedtls.MbedTLSArgumentValueFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/** Detection rules for mbedTLS legacy cipher descriptors and precise PSA AEAD constants. */
public final class MbedTLSCipher {

    private static final String BUNDLE = "MbedTLS";

    private static final IDetectionRule<AstNode> MBEDTLS_CIPHER_INFO_FROM_TYPE =
            cipherRule(0, "mbedtls_cipher_info_from_type");

    private static final IDetectionRule<AstNode> PSA_AEAD_ONE_SHOT =
            cipherRule(1, "psa_aead_encrypt", "psa_aead_decrypt");

    private static final IDetectionRule<AstNode> PSA_AEAD_SETUP =
            cipherRule(2, "psa_aead_encrypt_setup", "psa_aead_decrypt_setup");

    private MbedTLSCipher() {
        // private
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(MBEDTLS_CIPHER_INFO_FROM_TYPE, PSA_AEAD_ONE_SHOT, PSA_AEAD_SETUP);
    }

    @Nonnull
    private static IDetectionRule<AstNode> cipherRule(int argumentIndex, String... methods) {
        return new DetectionRuleBuilder<AstNode>()
                .createDetectionRule()
                .forObjectTypes("*")
                .forMethods(methods)
                .shouldBeDetectedAs(
                        new MbedTLSArgumentValueFactory(
                                argumentIndex, MbedTLSAlgorithmNames.CIPHERS))
                .withAnyParameters()
                .buildForContext(new CipherContext())
                .inBundle(() -> BUNDLE)
                .withoutDependingDetectionRules();
    }
}
