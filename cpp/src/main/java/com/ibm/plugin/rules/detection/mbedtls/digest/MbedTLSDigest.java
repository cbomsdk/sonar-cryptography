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
package com.ibm.plugin.rules.detection.mbedtls.digest;

import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.factory.IActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.mbedtls.MbedTLSAlgorithmNames;
import com.ibm.plugin.rules.detection.mbedtls.MbedTLSArgumentValueFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/** Detection rules for mbedTLS message digest and PSA hash APIs. */
public final class MbedTLSDigest {

    private static final String BUNDLE = "MbedTLS";

    private static final IDetectionRule<AstNode> MBEDTLS_MD_INFO_FROM_TYPE =
            digestRule(0, "mbedtls_md_info_from_type");

    private static final IDetectionRule<AstNode> MBEDTLS_X509_CRT_MD_ALG =
            digestRule(1, "mbedtls_x509write_crt_set_md_alg");

    private static final IDetectionRule<AstNode> MBEDTLS_X509_CSR_MD_ALG =
            digestRule(1, "mbedtls_x509write_csr_set_md_alg");

    private static final IDetectionRule<AstNode> PSA_HASH_COMPUTE =
            digestRule(0, "psa_hash_compute", "psa_hash_compare", "psa_hash_setup");

    private MbedTLSDigest() {
        // private
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                MBEDTLS_MD_INFO_FROM_TYPE,
                MBEDTLS_X509_CRT_MD_ALG,
                MBEDTLS_X509_CSR_MD_ALG,
                PSA_HASH_COMPUTE);
    }

    @Nonnull
    private static IDetectionRule<AstNode> digestRule(int argumentIndex, String... methods) {
        return rule(
                new MbedTLSArgumentValueFactory(argumentIndex, MbedTLSAlgorithmNames.DIGESTS),
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
                .buildForContext(new DigestContext())
                .inBundle(() -> BUNDLE)
                .withoutDependingDetectionRules();
    }
}
