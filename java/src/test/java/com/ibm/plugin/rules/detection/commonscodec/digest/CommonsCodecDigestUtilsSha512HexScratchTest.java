/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
import com.ibm.engine.model.context.DigestContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
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

class CommonsCodecDigestUtilsSha512HexScratchTest extends TestBase {

    @Test
    void detectsSupportedSha512HexCalls() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/commonscodec/digest/CommonsCodecDigestUtilsSha512HexScratchTestFile.java")
                .withChecks(this)
                .withClassPath(CommonsCodecJars.latestJar)
                .verifyIssues();
    }

    @Test
    void doesNotDetectWhenCommonsCodecTypeCannotBeResolved() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/commonscodec/digest/CommonsCodecDigestUtilsSha512HexNoClasspathScratchTestFile.java")
                .withChecks(this)
                .verifyNoIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(DigestContext.class);
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValues().get(0).asString()).isEqualTo("SHA-512");
        assertThat(nodes).hasSize(1);
        assertThat(nodes.get(0)).isInstanceOf(MessageDigest.class);
        assertThat(nodes.get(0).asString()).isEqualTo("SHA512");
    }
}
