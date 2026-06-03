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
package com.ibm.plugin.rules.detection.openssl.digest;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.TestBase;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

class OpenSSLEvpMessageDigestTest extends TestBase {

    private int findings;

    @Test
    void test() {
        CxxVerifier.verify(
                "rules/detection/openssl/digest/OpenSSLEvpMessageDigestTestFile.cpp", this);

        assertThat(findings).isEqualTo(1);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<
                                    SquidCheck<?>,
                                    AstNode,
                                    Symbol,
                                    SquidAstVisitorContext<? extends Grammar>>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        findings++;

        assertThat(findingId).isZero();
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(DigestContext.class);
        assertThat(detectionStore.getDetectionValues()).hasSize(1);

        IValue<AstNode> value = detectionStore.getDetectionValues().get(0);
        assertThat(value).isInstanceOf(ValueAction.class);
        assertThat(value.asString()).isEqualTo("SHA-256");

        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node).isInstanceOf(MessageDigest.class);
        assertThat(node.asString()).isEqualTo("SHA256");

        INode digestSize = node.getChildren().get(DigestSize.class);
        assertThat(digestSize).isNotNull();
        assertThat(digestSize.asString()).isEqualTo("256");

        INode function = node.getChildren().get(Digest.class);
        assertThat(function).isNotNull();

        INode oid = node.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.asString()).isEqualTo("2.16.840.1.101.3.4.2.1");

        INode blockSize = node.getChildren().get(BlockSize.class);
        assertThat(blockSize).isNotNull();
        assertThat(blockSize.asString()).isEqualTo("512");
    }
}
