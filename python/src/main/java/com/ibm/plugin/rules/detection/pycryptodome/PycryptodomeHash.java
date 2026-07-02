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
package com.ibm.plugin.rules.detection.pycryptodome;

import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.LinkedList;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

public final class PycryptodomeHash {

    private static final List<HashModule> HASHES =
            List.of(
                    new HashModule("SHA1", "SHA1"),
                    new HashModule("SHA224", "SHA224"),
                    new HashModule("SHA256", "SHA256"),
                    new HashModule("SHA384", "SHA384"),
                    new HashModule("SHA512", "SHA512"),
                    new HashModule("SHA3_224", "SHA3_224"),
                    new HashModule("SHA3_256", "SHA3_256"),
                    new HashModule("SHA3_384", "SHA3_384"),
                    new HashModule("SHA3_512", "SHA3_512"),
                    new HashModule("SHAKE128", "SHAKE128"),
                    new HashModule("SHAKE256", "SHAKE256"),
                    new HashModule("cSHAKE128", "cSHAKE128"),
                    new HashModule("cSHAKE256", "cSHAKE256"),
                    new HashModule("TupleHash128", "TupleHash128"),
                    new HashModule("TupleHash256", "TupleHash256"),
                    new HashModule("KangarooTwelve", "KangarooTwelve"),
                    new HashModule("BLAKE2b", "BLAKE2b"),
                    new HashModule("BLAKE2s", "BLAKE2s"),
                    new HashModule("MD2", "MD2"),
                    new HashModule("MD4", "MD4"),
                    new HashModule("MD5", "MD5"),
                    new HashModule("RIPEMD160", "RIPEMD160"),
                    new HashModule("Keccak", "Keccak"),
                    new HashModule("SM3", "SM3"));

    private PycryptodomeHash() {
        // utility
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        List<IDetectionRule<Tree>> rules = new LinkedList<>();
        for (HashModule hash : HASHES) {
            rules.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes(Pycryptodome.types("Hash." + hash.module()))
                            .forMethods("new")
                            .shouldBeDetectedAs(new ValueActionFactory<>(hash.algorithm()))
                            .withAnyParameters()
                            .buildForContext(new DigestContext())
                            .inBundle(() -> "PyCryptodome")
                            .withoutDependingDetectionRules());
        }
        return rules;
    }

    private record HashModule(String module, String algorithm) {}
}
