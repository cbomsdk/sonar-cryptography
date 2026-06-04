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
package com.ibm.plugin.rules.detection.openhitls.digest;

import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.openhitls.OpenHiTLSAlgorithmNames;
import com.ibm.plugin.rules.detection.openhitls.OpenHiTLSArgumentValueFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/** Detection rules for openHiTLS EAL digest APIs. */
public final class OpenHiTLSDigest {

    private static final String BUNDLE = "openHiTLS";

    private static final IDetectionRule<AstNode> EAL_MD =
            digestRule(0, "CRYPT_EAL_MdNewCtx", "CRYPT_EAL_Md");

    private static final IDetectionRule<AstNode> EAL_PROVIDER_MD =
            digestRule(1, "CRYPT_EAL_ProviderMdNewCtx", "CRYPT_EAL_ProviderMd");

    private static final IDetectionRule<AstNode> EAL_MD_MB = digestRule(1, "CRYPT_EAL_MdMBNewCtx");

    private OpenHiTLSDigest() {
        // private
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(EAL_MD, EAL_PROVIDER_MD, EAL_MD_MB);
    }

    @Nonnull
    private static IDetectionRule<AstNode> digestRule(int argumentIndex, String... methods) {
        return new DetectionRuleBuilder<AstNode>()
                .createDetectionRule()
                .forObjectTypes("*")
                .forMethods(methods)
                .shouldBeDetectedAs(
                        new OpenHiTLSArgumentValueFactory(
                                argumentIndex, OpenHiTLSAlgorithmNames.DIGESTS))
                .withAnyParameters()
                .buildForContext(new DigestContext())
                .inBundle(() -> BUNDLE)
                .withoutDependingDetectionRules();
    }
}
