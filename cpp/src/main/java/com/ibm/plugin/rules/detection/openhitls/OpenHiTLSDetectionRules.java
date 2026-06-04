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
package com.ibm.plugin.rules.detection.openhitls;

import com.ibm.engine.rule.IDetectionRule;
import com.ibm.plugin.rules.detection.openhitls.cipher.OpenHiTLSCipher;
import com.ibm.plugin.rules.detection.openhitls.digest.OpenHiTLSDigest;
import com.ibm.plugin.rules.detection.openhitls.kdf.OpenHiTLSKdf;
import com.ibm.plugin.rules.detection.openhitls.keyagreement.OpenHiTLSKeyAgreement;
import com.ibm.plugin.rules.detection.openhitls.mac.OpenHiTLSMac;
import com.ibm.plugin.rules.detection.openhitls.rand.OpenHiTLSRand;
import com.ibm.plugin.rules.detection.openhitls.signature.OpenHiTLSSignature;
import com.ibm.plugin.rules.detection.openhitls.ssl.OpenHiTLSSsl;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/** Aggregates openHiTLS cryptography and TLS detection rules for C/C++ analysis. */
public final class OpenHiTLSDetectionRules {

    private OpenHiTLSDetectionRules() {
        // private
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return Stream.of(
                        OpenHiTLSDigest.rules().stream(),
                        OpenHiTLSCipher.rules().stream(),
                        OpenHiTLSMac.rules().stream(),
                        OpenHiTLSKdf.rules().stream(),
                        OpenHiTLSSignature.rules().stream(),
                        OpenHiTLSKeyAgreement.rules().stream(),
                        OpenHiTLSRand.rules().stream(),
                        OpenHiTLSSsl.rules().stream())
                .flatMap(i -> i)
                .toList();
    }
}
