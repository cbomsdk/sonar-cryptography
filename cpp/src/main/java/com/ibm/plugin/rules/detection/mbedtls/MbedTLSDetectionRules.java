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
package com.ibm.plugin.rules.detection.mbedtls;

import com.ibm.engine.rule.IDetectionRule;
import com.ibm.plugin.rules.detection.mbedtls.cipher.MbedTLSCipher;
import com.ibm.plugin.rules.detection.mbedtls.digest.MbedTLSDigest;
import com.ibm.plugin.rules.detection.mbedtls.kdf.MbedTLSKdf;
import com.ibm.plugin.rules.detection.mbedtls.keyagreement.MbedTLSKeyAgreement;
import com.ibm.plugin.rules.detection.mbedtls.mac.MbedTLSMac;
import com.ibm.plugin.rules.detection.mbedtls.rand.MbedTLSRand;
import com.ibm.plugin.rules.detection.mbedtls.signature.MbedTLSSignature;
import com.ibm.plugin.rules.detection.mbedtls.ssl.MbedTLSSsl;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/** Aggregates mbedTLS and PSA Crypto detection rules for C/C++ analysis. */
public final class MbedTLSDetectionRules {

    private MbedTLSDetectionRules() {
        // private
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return Stream.of(
                        MbedTLSDigest.rules().stream(),
                        MbedTLSCipher.rules().stream(),
                        MbedTLSMac.rules().stream(),
                        MbedTLSKdf.rules().stream(),
                        MbedTLSSignature.rules().stream(),
                        MbedTLSKeyAgreement.rules().stream(),
                        MbedTLSRand.rules().stream(),
                        MbedTLSSsl.rules().stream())
                .flatMap(i -> i)
                .toList();
    }
}
