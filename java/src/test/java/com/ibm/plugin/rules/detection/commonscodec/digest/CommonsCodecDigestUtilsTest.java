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

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.plugin.TestBase;
import com.ibm.plugin.rules.detection.commonscodec.CommonsCodecJars;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class CommonsCodecDigestUtilsTest extends TestBase {

    private static final List<String> DETECTED_ALGORITHMS =
            List.of(
                    "MD2",
                    "MD5",
                    "SHA-1",
                    "SHA-1",
                    "SHA-224",
                    "SHA-256",
                    "SHA-384",
                    "SHA-512",
                    "SHA-512/224",
                    "SHA-512/256",
                    "SHA3-224",
                    "SHA3-256",
                    "SHA3-384",
                    "SHA3-512",
                    "SHA-512",
                    "SHA-384",
                    "SHA-512");

    private static final List<String> TRANSLATED_ALGORITHMS =
            List.of(
                    "MD2",
                    "MD5",
                    "SHA1",
                    "SHA1",
                    "SHA224",
                    "SHA256",
                    "SHA384",
                    "SHA512",
                    "SHA512/224",
                    "SHA512/256",
                    "SHA3-224",
                    "SHA3-256",
                    "SHA3-384",
                    "SHA3-512",
                    "SHA512",
                    "SHA384",
                    "SHA512");

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/commonscodec/digest/CommonsCodecDigestUtilsTestFile.java")
                .withChecks(this)
                .withClassPath(CommonsCodecJars.latestJar)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(findingId).isLessThan(DETECTED_ALGORITHMS.size());

        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<Tree> value = detectionStore.getDetectionValues().get(0);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(DigestContext.class);
        assertThat(value).isInstanceOfAny(Algorithm.class, ValueAction.class);
        assertThat(value.asString()).isEqualTo(DETECTED_ALGORITHMS.get(findingId));

        assertThat(nodes).hasSize(1);
        INode digestNode = nodes.get(0);
        assertThat(digestNode).isInstanceOf(MessageDigest.class);
        assertThat(digestNode.asString()).isEqualTo(TRANSLATED_ALGORITHMS.get(findingId));
        assertThat(digestNode.getChildren().get(Digest.class)).isNotNull();
    }
}
