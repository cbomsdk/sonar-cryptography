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
package com.ibm.plugin.rules.detection.mbedtls.kdf;

import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.mbedtls.MbedTLSHashPrefixedValueFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/** Detection rules for PSA key derivation algorithm macros used by mbedTLS. */
public final class MbedTLSKdf {

    private static final String BUNDLE = "MbedTLS";

    private static final IDetectionRule<AstNode> PSA_HKDF =
            hashRule("HKDF-", "PSA_ALG_HKDF", "PSA_ALG_HKDF_EXTRACT", "PSA_ALG_HKDF_EXPAND");

    private static final IDetectionRule<AstNode> PSA_TLS12_PRF =
            hashRule("TLS1-PRF-", "PSA_ALG_TLS12_PRF", "PSA_ALG_TLS12_PSK_TO_MS");

    private static final IDetectionRule<AstNode> PSA_PBKDF2_HMAC =
            hashRule("PBKDF2-HMAC-", "PSA_ALG_PBKDF2_HMAC");

    private MbedTLSKdf() {
        // private
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(PSA_HKDF, PSA_TLS12_PRF, PSA_PBKDF2_HMAC);
    }

    @Nonnull
    private static IDetectionRule<AstNode> hashRule(@Nonnull String prefix, String... methods) {
        return new DetectionRuleBuilder<AstNode>()
                .createDetectionRule()
                .forObjectTypes("*")
                .forMethods(methods)
                .shouldBeDetectedAs(new MbedTLSHashPrefixedValueFactory(0, prefix))
                .withAnyParameters()
                .buildForContext(new KeyDerivationFunctionContext())
                .inBundle(() -> BUNDLE)
                .withoutDependingDetectionRules();
    }
}
