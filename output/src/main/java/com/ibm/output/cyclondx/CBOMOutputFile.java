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
package com.ibm.output.cyclondx;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.CipherSuite;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.IAsset;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.IProperty;
import com.ibm.mapper.model.InitializationVectorLength;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.NonceLength;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.ParameterSetIdentifier;
import com.ibm.mapper.model.PasswordLength;
import com.ibm.mapper.model.Protocol;
import com.ibm.mapper.model.SaltLength;
import com.ibm.mapper.model.collections.CipherSuiteCollection;
import com.ibm.mapper.model.collections.TlsGroupCollection;
import com.ibm.mapper.model.collections.TlsSignatureSchemeCollection;
import com.ibm.mapper.model.functionality.Decapsulate;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.model.functionality.Encapsulate;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.model.functionality.Functionality;
import com.ibm.mapper.model.functionality.Generate;
import com.ibm.mapper.model.functionality.KeyDerivation;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Tag;
import com.ibm.mapper.model.functionality.Verify;
import com.ibm.mapper.model.padding.OAEP;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.output.Constants;
import com.ibm.output.IOutputFile;
import com.ibm.output.cyclondx.builder.AlgorithmComponentBuilder;
import com.ibm.output.cyclondx.builder.ProtocolComponentBuilder;
import com.ibm.output.cyclondx.builder.RelatedCryptoMaterialComponentBuilder;
import com.ibm.output.util.Utils;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.apache.commons.io.FileUtils;
import org.cyclonedx.Version;
import org.cyclonedx.exception.GeneratorException;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.generators.json.BomJsonGenerator;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.OrganizationalEntity;
import org.cyclonedx.model.Service;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.ProtocolProperties;
import org.cyclonedx.model.component.crypto.RelatedCryptographicAsset;
import org.cyclonedx.model.component.crypto.enums.ProtocolType;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.cyclonedx.model.metadata.ToolInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CBOMOutputFile implements IOutputFile {
    private static final Logger LOGGER = LoggerFactory.getLogger(CBOMOutputFile.class);
    private static final Version schema = Version.VERSION_17;
    private static final String TLS_CONFIGURATION_CIPHER_SUITE = "TLS configuration";

    @Nonnull private final Map<String, Component> components;
    @Nonnull private final Map<String, Dependency> dependencies;

    public CBOMOutputFile() {
        this.components = new HashMap<>();
        this.dependencies = new HashMap<>();
    }

    @Override
    public void add(@Nonnull List<INode> nodes) {
        add(null, nodes);
    }

    private void add(@Nullable final String parentBomRef, @Nonnull List<INode> nodes) {
        nodes.forEach(
                node -> {
                    // switch for asset
                    if (node instanceof Algorithm algorithm) {
                        createAlgorithmComponent(parentBomRef, algorithm);
                    } else if (node instanceof Key key) {
                        createKeyComponent(parentBomRef, key);
                    } else if (node instanceof Protocol protocol) {
                        createProtocolComponent(parentBomRef, protocol);
                    } else if (node instanceof CipherSuite cipherSuite) {
                        createCipherSuiteComponent(parentBomRef, cipherSuite);
                    } else if (node instanceof SaltLength
                            || node instanceof PasswordLength
                            || node instanceof InitializationVectorLength
                            || node instanceof NonceLength) {
                        final IProperty property = (IProperty) node;
                        createRelatedCryptoMaterialComponent(parentBomRef, property);
                    } else if (node.hasChildren()) {
                        add(parentBomRef, node.getChildren().values().stream().toList());
                    }
                });
    }

    @Nullable private String createAlgorithmComponent(
            @Nullable String parentBomRef, @Nonnull Algorithm node) {
        Map<Class<? extends INode>, INode> children = node.getChildren();
        Component algorithm =
                AlgorithmComponentBuilder.create()
                        .algorithm(node)
                        .mode(children.get(Mode.class))
                        .curve(children.get(EllipticCurve.class))
                        .parameterSetIdentifier(
                                Utils.oneOf(
                                        children.get(KeyLength.class),
                                        children.get(DigestSize.class),
                                        children.get(BlockSize.class),
                                        children.get(ParameterSetIdentifier.class)))
                        .padding(Utils.oneOf(children.get(OAEP.class), children.get(Padding.class)))
                        .cryptoFunctions(
                                Utils.allExisting(
                                        children.get(Decapsulate.class),
                                        children.get(Decrypt.class),
                                        children.get(Digest.class),
                                        children.get(Encapsulate.class),
                                        children.get(Encrypt.class),
                                        children.get(Generate.class),
                                        children.get(KeyDerivation.class),
                                        children.get(KeyGeneration.class),
                                        children.get(Sign.class),
                                        children.get(Tag.class),
                                        children.get(Verify.class)))
                        .primitive(node)
                        .occurrences(createOccurrenceForm(node.getDetectionContext()))
                        .oid(children.get(Oid.class))
                        .build();
        final Optional<String> optionalId = getIdentifierFunction().apply(algorithm);
        if (optionalId.isEmpty()) {
            return null;
        }
        addComponentAndDependencies(algorithm, optionalId.get(), parentBomRef, node);
        return this.components.get(optionalId.get()).getBomRef();
    }

    private void createKeyComponent(@Nullable String parentBomRef, @Nonnull Key node) {
        // if functionality nodes are placed under the key node,
        // they will be moved under the corresponding primitive node.
        Utils.pushNodesDownToFirstMatch(node, IPrimitive.getKinds(), Functionality.getKinds());
        // if a key length is defined under the key node, this function makes sure that the
        // underlying primitive
        // will get the same key length associated.
        Utils.pushNodesDownToFirstMatch(
                node, IPrimitive.getKinds(), List.of(KeyLength.class), false);

        createRelatedCryptoMaterialComponent(parentBomRef, node);
    }

    private void createProtocolComponent(@Nullable String parentBomRef, @Nonnull Protocol node) {
        Map<Class<? extends INode>, INode> children = node.getChildren();
        Component protocol =
                ProtocolComponentBuilder.create(this::createAlgorithmComponent)
                        .name(node)
                        .type(node)
                        .version(children.get(com.ibm.mapper.model.Version.class))
                        .tlsGroups(children.get(TlsGroupCollection.class))
                        .tlsSignatureSchemes(children.get(TlsSignatureSchemeCollection.class))
                        .cipherSuites(children.get(CipherSuiteCollection.class))
                        .occurrences(createOccurrenceForm(node.getDetectionContext()))
                        .build();
        final Optional<String> optionalId = getIdentifierFunction().apply(protocol);
        if (optionalId.isEmpty()) {
            return;
        }
        addComponentAndDependencies(protocol, optionalId.get(), parentBomRef, node);
    }

    private void createCipherSuiteComponent(
            @Nullable String parentBomRef, @Nonnull CipherSuite node) {
        final TLS tls = new TLS(node.getDetectionContext());
        Component protocol =
                ProtocolComponentBuilder.create(this::createAlgorithmComponent)
                        .name(tls)
                        .type(tls)
                        .version(null)
                        .tlsGroups(null)
                        .tlsSignatureSchemes(null)
                        .cipherSuites(new CipherSuiteCollection(List.of(node)))
                        .occurrences(createOccurrenceForm(node.getDetectionContext()))
                        .build();
        final Optional<String> optionalId = getIdentifierFunction().apply(protocol);
        if (optionalId.isEmpty()) {
            return;
        }
        addComponentAndDependencies(protocol, optionalId.get(), parentBomRef, node);
    }

    private void createRelatedCryptoMaterialComponent(
            @Nullable String parentBomRef, @Nonnull INode node) {
        Map<Class<? extends INode>, INode> children = node.getChildren();
        final DetectionLocation detectionLocation;
        if (node instanceof IProperty property) {
            detectionLocation = property.getDetectionContext();
        } else if (node instanceof IAsset iAsset) {
            detectionLocation = iAsset.getDetectionContext();
        } else {
            return;
        }
        Component rcm =
                RelatedCryptoMaterialComponentBuilder.create()
                        .name(node)
                        .size(Utils.oneOf(children.get(KeyLength.class), node))
                        .type(node)
                        .occurrences(createOccurrenceForm(detectionLocation))
                        .build();
        final Optional<String> optionalId = getIdentifierFunction().apply(rcm);
        if (optionalId.isEmpty()) {
            return;
        }
        addComponentAndDependencies(rcm, optionalId.get(), parentBomRef, node);
    }

    private void addComponentAndDependencies(
            @Nonnull final Component component,
            @Nonnull String componentId,
            @Nullable String parentBomRef,
            @Nonnull INode node) {
        String incomingBomRef = component.getBomRef();
        if (components.get(componentId) == null) {
            this.components.putIfAbsent(componentId, component);
        } else {
            this.components.computeIfPresent(
                    componentId,
                    (id, c) -> {
                        final List<Occurrence> merge =
                                Stream.concat(
                                                c.getEvidence().getOccurrences().stream(),
                                                component.getEvidence().getOccurrences().stream())
                                        .filter(
                                                com.ibm.output.cyclondx.builder.Utils.distinctByKey(
                                                        o ->
                                                                o.getLocation()
                                                                        + " "
                                                                        + o.getLine()
                                                                        + " "
                                                                        + o.getOffset()
                                                                        + " "
                                                                        + o.getAdditionalContext()
                                                                        + " "))
                                        .toList();
                        c.getEvidence().setOccurrences(merge);
                        mergeCryptoProperties(c, component);
                        mergeDependencies(incomingBomRef, c.getBomRef());
                        return c;
                    });
        }

        Component componentIdentify = this.components.get(componentId);
        if (parentBomRef != null) {
            Dependency newDependency = new Dependency(componentIdentify.getBomRef());
            if (dependencies.get(parentBomRef) == null) {
                Dependency parent = new Dependency(parentBomRef);
                parent.addDependency(newDependency);
                this.dependencies.putIfAbsent(parentBomRef, parent);
            } else {
                this.dependencies.computeIfPresent(
                        parentBomRef,
                        (s, d) -> {
                            d.addDependency(newDependency);
                            return d;
                        });
            }
        }

        if (node.hasChildren()) {
            add(componentIdentify.getBomRef(), node.getChildren().values().stream().toList());
        }
    }

    private void mergeDependencies(@Nonnull String incomingBomRef, @Nonnull String existingBomRef) {
        if (incomingBomRef.equals(existingBomRef)) {
            return;
        }
        Dependency incomingDependency = dependencies.remove(incomingBomRef);
        if (incomingDependency == null) {
            return;
        }
        Dependency existingDependency =
                dependencies.computeIfAbsent(existingBomRef, Dependency::new);
        incomingDependency.getDependencies().forEach(existingDependency::addDependency);
    }

    private void mergeCryptoProperties(
            @Nonnull Component existingComponent, @Nonnull Component newComponent) {
        CryptoProperties existing = existingComponent.getCryptoProperties();
        CryptoProperties incoming = newComponent.getCryptoProperties();
        if (incoming == null) {
            return;
        }
        if (existing == null) {
            existingComponent.setCryptoProperties(incoming);
            return;
        }
        mergeProtocolProperties(existing.getProtocolProperties(), incoming.getProtocolProperties());
    }

    private void mergeProtocolProperties(
            @Nullable ProtocolProperties existing, @Nullable ProtocolProperties incoming) {
        if (existing == null || incoming == null) {
            return;
        }
        if (shouldReplaceProtocolType(existing.getType(), incoming.getType())) {
            existing.setType(incoming.getType());
        }
        if (incoming.getVersion() != null) {
            existing.setVersion(incoming.getVersion());
        }
        if (existing.getCipherSuites() == null) {
            existing.setCipherSuites(incoming.getCipherSuites());
        } else if (incoming.getCipherSuites() != null) {
            existing.setCipherSuites(
                    mergeCipherSuites(existing.getCipherSuites(), incoming.getCipherSuites()));
        }
        if (existing.getCryptoRefArray() == null) {
            existing.setCryptoRefArray(incoming.getCryptoRefArray());
        } else if (incoming.getCryptoRefArray() != null) {
            List<String> mergedCryptoRefs = new ArrayList<>(existing.getCryptoRefArray());
            incoming.getCryptoRefArray().stream()
                    .filter(cryptoRef -> !mergedCryptoRefs.contains(cryptoRef))
                    .forEach(mergedCryptoRefs::add);
            existing.setCryptoRefArray(mergedCryptoRefs);
        }
        if (existing.getRelatedCryptographicAssets() == null) {
            existing.setRelatedCryptographicAssets(incoming.getRelatedCryptographicAssets());
        } else if (incoming.getRelatedCryptographicAssets() != null) {
            List<RelatedCryptographicAsset> mergedRelatedAssets =
                    new ArrayList<>(existing.getRelatedCryptographicAssets());
            incoming.getRelatedCryptographicAssets().stream()
                    .filter(relatedAsset -> !mergedRelatedAssets.contains(relatedAsset))
                    .forEach(mergedRelatedAssets::add);
            existing.setRelatedCryptographicAssets(mergedRelatedAssets);
        }
        if (existing.getIkev2TransformTypes() == null) {
            existing.setIkev2TransformTypes(incoming.getIkev2TransformTypes());
        }
    }

    private boolean shouldReplaceProtocolType(
            @Nullable ProtocolType existing, @Nullable ProtocolType incoming) {
        return incoming != null
                && (existing == null
                        || existing == ProtocolType.UNKNOWN
                        || existing == ProtocolType.OTHER)
                && incoming != ProtocolType.UNKNOWN
                && incoming != ProtocolType.OTHER;
    }

    @Nonnull
    private List<org.cyclonedx.model.component.crypto.CipherSuite> mergeCipherSuites(
            @Nonnull List<org.cyclonedx.model.component.crypto.CipherSuite> existing,
            @Nonnull List<org.cyclonedx.model.component.crypto.CipherSuite> incoming) {
        final List<org.cyclonedx.model.component.crypto.CipherSuite> existingConcreteSuites =
                existing.stream().filter(cipherSuite -> !isTlsConfiguration(cipherSuite)).toList();
        final List<org.cyclonedx.model.component.crypto.CipherSuite> incomingConcreteSuites =
                incoming.stream().filter(cipherSuite -> !isTlsConfiguration(cipherSuite)).toList();
        final boolean existingHasExplicitCipherSuites =
                existingConcreteSuites.stream().anyMatch(this::hasAlgorithmReferences);
        final boolean incomingHasExplicitCipherSuites =
                incomingConcreteSuites.stream().anyMatch(this::hasAlgorithmReferences);

        final List<org.cyclonedx.model.component.crypto.CipherSuite> mergedCipherSuites =
                new ArrayList<>();
        if (incomingHasExplicitCipherSuites) {
            existingConcreteSuites.stream()
                    .filter(this::hasAlgorithmReferences)
                    .forEach(
                            cipherSuite ->
                                    appendUniqueCipherSuite(mergedCipherSuites, cipherSuite));
            incomingConcreteSuites.forEach(
                    cipherSuite -> appendUniqueCipherSuite(mergedCipherSuites, cipherSuite));
        } else if (existingHasExplicitCipherSuites) {
            existingConcreteSuites.forEach(
                    cipherSuite -> appendUniqueCipherSuite(mergedCipherSuites, cipherSuite));
        } else {
            existingConcreteSuites.forEach(
                    cipherSuite -> appendUniqueCipherSuite(mergedCipherSuites, cipherSuite));
            incomingConcreteSuites.forEach(
                    cipherSuite -> appendUniqueCipherSuite(mergedCipherSuites, cipherSuite));
        }

        mergeTlsConfigurationCipherSuite(existing, incoming)
                .ifPresent(cipherSuite -> appendUniqueCipherSuite(mergedCipherSuites, cipherSuite));
        return mergedCipherSuites;
    }

    private boolean isTlsConfiguration(
            @Nonnull org.cyclonedx.model.component.crypto.CipherSuite cipherSuite) {
        return TLS_CONFIGURATION_CIPHER_SUITE.equals(cipherSuite.getName());
    }

    private boolean hasAlgorithmReferences(
            @Nonnull org.cyclonedx.model.component.crypto.CipherSuite cipherSuite) {
        return cipherSuite.getAlgorithms() != null && !cipherSuite.getAlgorithms().isEmpty();
    }

    private void appendUniqueCipherSuite(
            @Nonnull List<org.cyclonedx.model.component.crypto.CipherSuite> cipherSuites,
            @Nonnull org.cyclonedx.model.component.crypto.CipherSuite cipherSuite) {
        if (!cipherSuites.contains(cipherSuite)) {
            cipherSuites.add(cipherSuite);
        }
    }

    @Nonnull
    private Optional<org.cyclonedx.model.component.crypto.CipherSuite>
            mergeTlsConfigurationCipherSuite(
                    @Nonnull List<org.cyclonedx.model.component.crypto.CipherSuite> existing,
                    @Nonnull List<org.cyclonedx.model.component.crypto.CipherSuite> incoming) {
        final Optional<org.cyclonedx.model.component.crypto.CipherSuite> existingConfiguration =
                existing.stream().filter(this::isTlsConfiguration).findFirst();
        final Optional<org.cyclonedx.model.component.crypto.CipherSuite> incomingConfiguration =
                incoming.stream().filter(this::isTlsConfiguration).findFirst();
        if (existingConfiguration.isEmpty()) {
            return incomingConfiguration;
        }
        if (incomingConfiguration.isEmpty()) {
            return existingConfiguration;
        }

        final org.cyclonedx.model.component.crypto.CipherSuite mergedConfiguration =
                new org.cyclonedx.model.component.crypto.CipherSuite();
        mergedConfiguration.setName(TLS_CONFIGURATION_CIPHER_SUITE);
        selectConfiguredValues(
                        existingConfiguration.get().getTlsGroups(),
                        incomingConfiguration.get().getTlsGroups())
                .ifPresent(mergedConfiguration::setTlsGroups);
        selectConfiguredValues(
                        existingConfiguration.get().getTlsSignatureSchemes(),
                        incomingConfiguration.get().getTlsSignatureSchemes())
                .ifPresent(mergedConfiguration::setTlsSignatureSchemes);
        return Optional.of(mergedConfiguration);
    }

    @Nonnull
    private Optional<List<String>> selectConfiguredValues(
            @Nullable List<String> existing, @Nullable List<String> incoming) {
        if (existing == null || existing.isEmpty()) {
            return Optional.ofNullable(incoming).filter(values -> !values.isEmpty());
        }
        if (incoming == null || incoming.isEmpty()) {
            return Optional.of(existing);
        }
        if (existing.containsAll(incoming)) {
            return Optional.of(incoming);
        }
        if (incoming.containsAll(existing)) {
            return Optional.of(existing);
        }
        return Optional.of(incoming);
    }

    @Nonnull
    public Bom getBom() {
        final Bom bom = new Bom();
        bom.setSerialNumber("urn:uuid:" + UUID.randomUUID());
        // add metadata
        final Metadata metadata = new Metadata();
        metadata.setTimestamp(new Date());
        // add scanner to metadata
        final ToolInformation scannerInfo = new ToolInformation();
        final Service scannerService = new Service();
        scannerService.setName(Constants.SCANNER_NAME);
        final OrganizationalEntity organization = new OrganizationalEntity();
        organization.setName(Constants.SCANNER_VENDOR);
        scannerService.setProvider(organization);
        try {
            final Properties properties = new Properties();
            properties.load(
                    this.getClass().getClassLoader().getResourceAsStream("plugin.properties"));
            scannerService.setVersion(properties.getProperty("plugin.version"));
        } catch (Exception e) {
            scannerService.setVersion("0.0.0");
        }
        scannerInfo.setServices(List.of(scannerService));
        metadata.setToolChoice(scannerInfo);
        bom.setMetadata(metadata);
        bom.setComponents(new ArrayList<>(this.components.values()));
        bom.setDependencies(new ArrayList<>(this.dependencies.values()));
        return bom;
    }

    @Override
    public void saveTo(@Nonnull File file) {
        final Bom bom = getBom();
        final BomJsonGenerator bomGenerator = BomGeneratorFactory.createJson(schema, bom);
        try {
            final String bomString = bomGenerator.toJsonString();
            FileUtils.write(file, bomString, StandardCharsets.UTF_8, false);
        } catch (IOException e) {
            LOGGER.error("Could not write CBOM file: {}", e.getMessage());
        } catch (GeneratorException e) {
            LOGGER.error("Could not generate CBOM: {}", e.getMessage());
        }
    }

    @Nonnull
    private Function<Component, Optional<String>> getIdentifierFunction() {
        return (component -> Optional.ofNullable(component.getName()));
    }

    @Nonnull
    private Occurrence createOccurrenceForm(@Nonnull DetectionLocation detectionLocation) {
        final Occurrence occurrence = new Occurrence();
        occurrence.setLocation(detectionLocation.filePath());
        occurrence.setLine(detectionLocation.lineNumber());
        occurrence.setOffset(detectionLocation.offSet());
        if (!detectionLocation.keywords().isEmpty()) {
            occurrence.setAdditionalContext(detectionLocation.keywords().get(0));
        }
        return occurrence;
    }
}
