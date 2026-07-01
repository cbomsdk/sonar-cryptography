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
package com.ibm.plugin.rules.detection.asymmetric.RSA;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.MaskGenerationFunction;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.checks.utils.PythonCheckVerifier;

class PycaRSAEncryptTest extends TestBase {

    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/asymmetric/RSA/PycaRSAEncryptTestFile.py", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        if (detectionStore.getDetectionValueContext().is(PrivateKeyContext.class)) {
            assertPrivateKeyGeneration(detectionStore, nodes);
        } else {
            assertRsaOaepEncrypt(detectionStore, nodes);
        }
    }

    private void assertPrivateKeyGeneration(
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(KeySize.class);
        assertThat(value0.asString()).isEqualTo("2048");

        assertThat(nodes).hasSize(1);
        INode privateKeyNode = nodes.get(0);
        assertThat(privateKeyNode.getKind()).isEqualTo(PrivateKey.class);
        assertThat(privateKeyNode.asString()).isEqualTo("RSA");
        assertThat(privateKeyNode.getChildren().get(KeyGeneration.class)).isNotNull();
        assertThat(privateKeyNode.getChildren().get(KeyLength.class).asString()).isEqualTo("2048");
    }

    private void assertRsaOaepEncrypt(
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(CipherAction.class);
        assertThat(value0.asString()).isEqualTo("ENCRYPT");

        DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> paddingStore =
                getStoreOfValueType(ValueAction.class, detectionStore.getChildren());
        assertThat(paddingStore).isNotNull();
        assertThat(paddingStore.getDetectionValues().get(0).asString()).isEqualTo("OAEP");

        assertThat(nodes).hasSize(1);
        INode publicKeyEncryptionNode = nodes.get(0);
        assertThat(publicKeyEncryptionNode.getKind()).isEqualTo(PublicKeyEncryption.class);
        assertThat(publicKeyEncryptionNode.asString()).isEqualTo("RSA-OAEP");
        assertThat(publicKeyEncryptionNode.getChildren().get(Encrypt.class)).isNotNull();
        assertThat(publicKeyEncryptionNode.getChildren().get(Oid.class).asString())
                .isEqualTo("1.2.840.113549.1.1.7");

        INode paddingNode = publicKeyEncryptionNode.getChildren().get(Padding.class);
        assertThat(paddingNode).isNotNull();
        assertThat(paddingNode.asString()).isEqualTo("OAEP");
        assertThat(paddingNode.getChildren().get(MessageDigest.class).asString())
                .isEqualTo("SHA384");
        assertThat(paddingNode.getChildren().get(MaskGenerationFunction.class).asString())
                .isEqualTo("MGF1");
    }
}
