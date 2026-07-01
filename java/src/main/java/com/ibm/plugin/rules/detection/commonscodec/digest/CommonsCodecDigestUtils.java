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
package com.ibm.plugin.rules.detection.commonscodec.digest;

import static com.ibm.plugin.rules.detection.TypeShortcuts.STRING_TYPE;

import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.LinkedList;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class CommonsCodecDigestUtils {

    private static final String DIGEST_UTILS = "org.apache.commons.codec.digest.DigestUtils";

    private record MethodDigest(@Nonnull String methodName, @Nonnull String algorithm) {}

    private static final List<MethodDigest> FIXED_ALGORITHM_METHODS =
            List.of(
                    new MethodDigest("getMd2Digest", "MD2"),
                    new MethodDigest("getMd5Digest", "MD5"),
                    new MethodDigest("getShaDigest", "SHA-1"),
                    new MethodDigest("getSha1Digest", "SHA-1"),
                    new MethodDigest("getSha256Digest", "SHA-256"),
                    new MethodDigest("getSha3_224Digest", "SHA3-224"),
                    new MethodDigest("getSha3_256Digest", "SHA3-256"),
                    new MethodDigest("getSha3_384Digest", "SHA3-384"),
                    new MethodDigest("getSha3_512Digest", "SHA3-512"),
                    new MethodDigest("getSha384Digest", "SHA-384"),
                    new MethodDigest("getSha512Digest", "SHA-512"),
                    new MethodDigest("getSha512_224Digest", "SHA-512/224"),
                    new MethodDigest("getSha512_256Digest", "SHA-512/256"),
                    new MethodDigest("md2", "MD2"),
                    new MethodDigest("md2Hex", "MD2"),
                    new MethodDigest("md5", "MD5"),
                    new MethodDigest("md5Hex", "MD5"),
                    new MethodDigest("sha", "SHA-1"),
                    new MethodDigest("shaHex", "SHA-1"),
                    new MethodDigest("sha1", "SHA-1"),
                    new MethodDigest("sha1Hex", "SHA-1"),
                    new MethodDigest("sha256", "SHA-256"),
                    new MethodDigest("sha256Hex", "SHA-256"),
                    new MethodDigest("sha384", "SHA-384"),
                    new MethodDigest("sha384Hex", "SHA-384"),
                    new MethodDigest("sha512", "SHA-512"),
                    new MethodDigest("sha512Hex", "SHA-512"),
                    new MethodDigest("sha512_224", "SHA-512/224"),
                    new MethodDigest("sha512_224Hex", "SHA-512/224"),
                    new MethodDigest("sha512_256", "SHA-512/256"),
                    new MethodDigest("sha512_256Hex", "SHA-512/256"),
                    new MethodDigest("sha3_224", "SHA3-224"),
                    new MethodDigest("sha3_224Hex", "SHA3-224"),
                    new MethodDigest("sha3_256", "SHA3-256"),
                    new MethodDigest("sha3_256Hex", "SHA3-256"),
                    new MethodDigest("sha3_384", "SHA3-384"),
                    new MethodDigest("sha3_384Hex", "SHA3-384"),
                    new MethodDigest("sha3_512", "SHA3-512"),
                    new MethodDigest("sha3_512Hex", "SHA3-512"));

    private static final IDetectionRule<Tree> GET_DIGEST =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(DIGEST_UTILS)
                    .forMethods("getDigest")
                    .withMethodParameter(STRING_TYPE)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> GET_DIGEST_WITH_DEFAULT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(DIGEST_UTILS)
                    .forMethods("getDigest")
                    .withMethodParameter(STRING_TYPE)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("java.security.MessageDigest")
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CONSTRUCTOR_WITH_ALGORITHM =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(DIGEST_UTILS)
                    .forConstructor()
                    .withMethodParameter(STRING_TYPE)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "Jca")
                    .withoutDependingDetectionRules();

    private CommonsCodecDigestUtils() {
        // nothing
    }

    private static @Nonnull List<IDetectionRule<Tree>> fixedAlgorithmMethods() {
        List<IDetectionRule<Tree>> rules = new LinkedList<>();

        for (MethodDigest methodDigest : FIXED_ALGORITHM_METHODS) {
            rules.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes(DIGEST_UTILS)
                            .forMethods(methodDigest.methodName())
                            .shouldBeDetectedAs(new ValueActionFactory<>(methodDigest.algorithm()))
                            .withAnyParameters()
                            .buildForContext(new DigestContext())
                            .inBundle(() -> "Jca")
                            .withoutDependingDetectionRules());
        }

        return rules;
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        List<IDetectionRule<Tree>> rules = new LinkedList<>();
        rules.addAll(fixedAlgorithmMethods());
        rules.add(GET_DIGEST);
        rules.add(GET_DIGEST_WITH_DEFAULT);
        rules.add(CONSTRUCTOR_WITH_ALGORITHM);
        return rules;
    }
}
