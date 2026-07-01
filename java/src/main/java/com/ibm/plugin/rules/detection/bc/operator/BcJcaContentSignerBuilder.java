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

import static com.ibm.plugin.rules.detection.TypeShortcuts.STRING_TYPE;

import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcJcaContentSignerBuilder {

    private static final String CLASS_NAME =
            "org.bouncycastle.operator.jcajce.JcaContentSignerBuilder";

    private static final IDetectionRule<Tree> CONSTRUCTOR_ALGORITHM =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(CLASS_NAME)
                    .forConstructor()
                    .withMethodParameter(STRING_TYPE)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CONSTRUCTOR_ALGORITHM_PUBLIC_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(CLASS_NAME)
                    .forConstructor()
                    .withMethodParameter(STRING_TYPE)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("java.security.PublicKey")
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CONSTRUCTOR_ALGORITHM_IDENTIFIER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(CLASS_NAME)
                    .forConstructor()
                    .withMethodParameter(STRING_TYPE)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("org.bouncycastle.asn1.x509.AlgorithmIdentifier")
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CONSTRUCTOR_ALGORITHM_PARAMETER_SPEC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(CLASS_NAME)
                    .forConstructor()
                    .withMethodParameter(STRING_TYPE)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("java.security.spec.AlgorithmParameterSpec")
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CONSTRUCTOR_ALGORITHM_PARAMETER_SPEC_IDENTIFIER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(CLASS_NAME)
                    .forConstructor()
                    .withMethodParameter(STRING_TYPE)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("java.security.spec.AlgorithmParameterSpec")
                    .withMethodParameter("org.bouncycastle.asn1.x509.AlgorithmIdentifier")
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private BcJcaContentSignerBuilder() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(
                CONSTRUCTOR_ALGORITHM,
                CONSTRUCTOR_ALGORITHM_PUBLIC_KEY,
                CONSTRUCTOR_ALGORITHM_IDENTIFIER,
                CONSTRUCTOR_ALGORITHM_PARAMETER_SPEC,
                CONSTRUCTOR_ALGORITHM_PARAMETER_SPEC_IDENTIFIER);
    }
}
