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
package com.ibm.plugin.translation.translator.contexts;

import com.ibm.engine.model.CipherSuite;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.mapper.ssl.CipherSuiteMapper;
import com.ibm.mapper.mapper.ssl.SSLVersionMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Protocol;
import com.ibm.mapper.model.TlsGroup;
import com.ibm.mapper.model.TlsSignatureScheme;
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.Version;
import com.ibm.mapper.model.collections.AssetCollection;
import com.ibm.mapper.model.collections.CipherSuiteCollection;
import com.ibm.mapper.model.collections.TlsGroupCollection;
import com.ibm.mapper.model.collections.TlsSignatureSchemeCollection;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.plugin.rules.detection.TlsConfigurationAction;
import com.ibm.plugin.rules.detection.openssl.ssl.OpenSSLVersionValue;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;

/** Translates C/C++ SSL/TLS protocol contexts to CBOM model nodes. */
public final class CxxProtocolContextTranslator implements IContextTranslation<AstNode> {

    @Nonnull
    @Override
    public Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<AstNode> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        final ProtocolContext.Kind kind = ((ProtocolContext) detectionContext).kind();

        // Handle OpenSSLVersionValue (custom value type with parameter extraction)
        if (value instanceof OpenSSLVersionValue versionValue) {
            final String versionString = versionValue.asString();
            if (kind == ProtocolContext.Kind.TLS) {
                final SSLVersionMapper sslVersionMapper = new SSLVersionMapper();
                final Optional<Version> parsedVersion =
                        sslVersionMapper.parse(versionString, detectionLocation);
                if (parsedVersion.isPresent()) {
                    return Optional.of(new TLS(parsedVersion.get()));
                }
                // Fallback to generic protocol if parsing fails
                return Optional.of(new Protocol(versionString, detectionLocation));
            }
            return Optional.of(new Protocol(versionString, detectionLocation));
        }

        if (value instanceof TlsConfigurationAction tlsConfiguration) {
            return Optional.of(toTlsNode(tlsConfiguration, detectionLocation));
        } else if (value instanceof com.ibm.engine.model.Protocol<AstNode> protocol) {
            return switch (kind) {
                case TLS ->
                        Optional.of(protocol)
                                .map(
                                        p -> {
                                            final SSLVersionMapper sslVersionMapper =
                                                    new SSLVersionMapper();
                                            return sslVersionMapper
                                                    .parse(p.asString(), detectionLocation)
                                                    .map(TLS::new)
                                                    .orElse(new TLS(detectionLocation));
                                        });
                default ->
                        Optional.of(protocol)
                                .map(p -> new Protocol(p.asString(), detectionLocation));
            };
        } else if (value instanceof CipherSuite<AstNode> cipherSuite) {
            return switch (kind) {
                case TLS ->
                        new CipherSuiteMapper()
                                .parse(cipherSuite.get(), detectionLocation)
                                .map(n -> n);
                default ->
                        Optional.of(cipherSuite)
                                .map(
                                        suite ->
                                                new com.ibm.mapper.model.CipherSuite(
                                                        suite.asString(), detectionLocation));
            };
        } else if (value instanceof ValueAction<AstNode> valueAction) {
            // Handle ValueAction instances from ValueActionFactory
            final String stringValue = valueAction.asString();
            if (kind == ProtocolContext.Kind.TLS) {
                // Try to parse as SSL version first
                final SSLVersionMapper sslVersionMapper = new SSLVersionMapper();
                final Optional<Version> parsedVersion =
                        sslVersionMapper.parse(stringValue, detectionLocation);
                if (parsedVersion.isPresent()) {
                    return Optional.of(new TLS(parsedVersion.get()));
                }
                return Optional.of(new TLS(detectionLocation));
            }
            // For non-TLS protocols, create generic Protocol node
            return Optional.of(new Protocol(stringValue, detectionLocation));
        }

        return Optional.of(new Unknown(detectionLocation));
    }

    @Nonnull
    private static TLS toTlsNode(
            @Nonnull TlsConfigurationAction tlsConfiguration,
            @Nonnull DetectionLocation detectionLocation) {
        TLS tls = new TLS(detectionLocation);
        if (tlsConfiguration.tlsVersion() != null) {
            tls.put(new Version(tlsConfiguration.tlsVersion(), detectionLocation));
        }
        List<com.ibm.mapper.model.CipherSuite> cipherSuites =
                tlsConfiguration.cipherSuites().stream()
                        .map(
                                cipherSuiteName ->
                                        new CipherSuiteMapper()
                                                .parse(cipherSuiteName, detectionLocation))
                        .flatMap(Optional::stream)
                        .filter(com.ibm.mapper.model.CipherSuite.class::isInstance)
                        .map(com.ibm.mapper.model.CipherSuite.class::cast)
                        .toList();

        if (!tlsConfiguration.includeCipherSuiteAlgorithms()) {
            cipherSuites.forEach(
                    cipherSuite -> cipherSuite.removeChildOfType(AssetCollection.class));
        }

        if (!tlsConfiguration.tlsGroups().isEmpty()
                || !tlsConfiguration.tlsSignatureSchemes().isEmpty()) {
            com.ibm.mapper.model.CipherSuite configuration =
                    new com.ibm.mapper.model.CipherSuite("TLS configuration", detectionLocation);
            List<com.ibm.mapper.model.CipherSuite> configuredCipherSuites =
                    new ArrayList<>(cipherSuites);
            configuredCipherSuites.add(
                    withTlsConfiguration(configuration, tlsConfiguration, detectionLocation));
            cipherSuites = configuredCipherSuites;
        }

        if (!cipherSuites.isEmpty()) {
            tls.put(new CipherSuiteCollection(cipherSuites));
        }
        return tls;
    }

    @Nonnull
    private static com.ibm.mapper.model.CipherSuite withTlsConfiguration(
            @Nonnull com.ibm.mapper.model.CipherSuite cipherSuite,
            @Nonnull TlsConfigurationAction tlsConfiguration,
            @Nonnull DetectionLocation detectionLocation) {
        if (!tlsConfiguration.tlsGroups().isEmpty()) {
            cipherSuite.put(
                    new TlsGroupCollection(
                            tlsConfiguration.tlsGroups().stream()
                                    .map(group -> new TlsGroup(group, detectionLocation))
                                    .toList()));
        }
        if (!tlsConfiguration.tlsSignatureSchemes().isEmpty()) {
            cipherSuite.put(
                    new TlsSignatureSchemeCollection(
                            tlsConfiguration.tlsSignatureSchemes().stream()
                                    .map(
                                            signatureScheme ->
                                                    new TlsSignatureScheme(
                                                            signatureScheme, detectionLocation))
                                    .toList()));
        }
        return cipherSuite;
    }
}
