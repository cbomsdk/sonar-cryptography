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

import com.ibm.plugin.rules.detection.TlsConfigurationAction;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public final class OpenHiTLSTlsConfigurationAction implements TlsConfigurationAction {

    @Nonnull private final List<String> cipherSuites;
    @Nonnull private final List<String> tlsGroups;
    @Nonnull private final List<String> tlsSignatureSchemes;
    @Nullable private final String tlsVersion;
    private final boolean includeCipherSuiteAlgorithms;
    @Nonnull private final AstNode location;

    public OpenHiTLSTlsConfigurationAction(
            @Nonnull List<String> cipherSuites,
            @Nonnull List<String> tlsGroups,
            @Nonnull List<String> tlsSignatureSchemes,
            @Nonnull AstNode location) {
        this(cipherSuites, tlsGroups, tlsSignatureSchemes, null, true, location);
    }

    public OpenHiTLSTlsConfigurationAction(
            @Nonnull List<String> cipherSuites,
            @Nonnull List<String> tlsGroups,
            @Nonnull List<String> tlsSignatureSchemes,
            @Nullable String tlsVersion,
            @Nonnull AstNode location) {
        this(cipherSuites, tlsGroups, tlsSignatureSchemes, tlsVersion, true, location);
    }

    public OpenHiTLSTlsConfigurationAction(
            @Nonnull List<String> cipherSuites,
            @Nonnull List<String> tlsGroups,
            @Nonnull List<String> tlsSignatureSchemes,
            @Nullable String tlsVersion,
            boolean includeCipherSuiteAlgorithms,
            @Nonnull AstNode location) {
        this.cipherSuites = List.copyOf(cipherSuites);
        this.tlsGroups = List.copyOf(tlsGroups);
        this.tlsSignatureSchemes = List.copyOf(tlsSignatureSchemes);
        this.tlsVersion = tlsVersion;
        this.includeCipherSuiteAlgorithms = includeCipherSuiteAlgorithms;
        this.location = location;
    }

    @Nonnull
    @Override
    public List<String> cipherSuites() {
        return cipherSuites;
    }

    @Nonnull
    @Override
    public List<String> tlsGroups() {
        return tlsGroups;
    }

    @Nonnull
    @Override
    public List<String> tlsSignatureSchemes() {
        return tlsSignatureSchemes;
    }

    @Nullable @Override
    public String tlsVersion() {
        return tlsVersion;
    }

    @Override
    public boolean includeCipherSuiteAlgorithms() {
        return includeCipherSuiteAlgorithms;
    }

    @Nonnull
    @Override
    public AstNode getLocation() {
        return location;
    }

    @Nonnull
    @Override
    public String asString() {
        if (tlsVersion != null) {
            return "TLS-DEFAULTS:" + tlsVersion;
        }
        if (!cipherSuites.isEmpty()) {
            return String.join(",", cipherSuites);
        }
        if (!tlsGroups.isEmpty()) {
            return "TLS-GROUPS:" + String.join(",", tlsGroups);
        }
        return "TLS-SIGNATURE-SCHEMES:" + String.join(",", tlsSignatureSchemes);
    }
}
