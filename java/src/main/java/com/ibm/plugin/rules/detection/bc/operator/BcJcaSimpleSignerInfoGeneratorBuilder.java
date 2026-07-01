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
package com.ibm.plugin.rules.detection.bc.operator;

import static com.ibm.plugin.rules.detection.TypeShortcuts.BYTE_ARRAY_TYPE;
import static com.ibm.plugin.rules.detection.TypeShortcuts.STRING_TYPE;

import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcJcaSimpleSignerInfoGeneratorBuilder {

    private static final String CLASS_NAME =
            "org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder";

    private static final IDetectionRule<Tree> BUILD_CERTIFICATE_HOLDER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(CLASS_NAME)
                    .forMethods("build")
                    .withMethodParameter(STRING_TYPE)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("java.security.PrivateKey")
                    .withMethodParameter("org.bouncycastle.cert.X509CertificateHolder")
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> BUILD_CERTIFICATE =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(CLASS_NAME)
                    .forMethods("build")
                    .withMethodParameter(STRING_TYPE)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("java.security.PrivateKey")
                    .withMethodParameter("java.security.cert.X509Certificate")
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> BUILD_SUBJECT_KEY_IDENTIFIER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(CLASS_NAME)
                    .forMethods("build")
                    .withMethodParameter(STRING_TYPE)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("java.security.PrivateKey")
                    .withMethodParameter(BYTE_ARRAY_TYPE)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private BcJcaSimpleSignerInfoGeneratorBuilder() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(BUILD_CERTIFICATE_HOLDER, BUILD_CERTIFICATE, BUILD_SUBJECT_KEY_IDENTIFIER);
    }
}
