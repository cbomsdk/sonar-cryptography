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
package com.ibm.plugin.rules.detection.hash;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.mapper.model.ExtendableOutputFunction;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.checks.utils.PythonCheckVerifier;

class HashlibHashTest extends TestBase {

    private static final List<String> EXPECTED_VALUES =
            List.of(
                    "SHA1",
                    "SHA256",
                    "SHA3_256",
                    "SHAKE128",
                    "BLAKE2b",
                    "MD5",
                    "sha512",
                    "shake_256");

    private static final List<String> EXPECTED_NODE_NAMES =
            List.of(
                    "SHA1",
                    "SHA256",
                    "SHA3-256",
                    "SHAKE128",
                    "BLAKE2b",
                    "MD5",
                    "SHA512",
                    "SHAKE256");

    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/hash/HashlibHashTestFile.py", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(findingId).isLessThan(EXPECTED_VALUES.size());

        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(DigestContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOfAny(ValueAction.class, Algorithm.class);
        assertThat(value0.asString()).isEqualTo(EXPECTED_VALUES.get(findingId));

        assertThat(nodes).hasSize(1);
        INode messageDigestNode = nodes.get(0);
        assertThat(messageDigestNode.getKind())
                .isIn(MessageDigest.class, ExtendableOutputFunction.class);
        assertThat(messageDigestNode.asString()).isEqualTo(EXPECTED_NODE_NAMES.get(findingId));

        INode digestNode = messageDigestNode.getChildren().get(Digest.class);
        assertThat(digestNode).isNotNull();
        assertThat(digestNode.asString()).isEqualTo("DIGEST");
    }
}
