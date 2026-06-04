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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;

/** Canonical algorithm-name mappings for mbedTLS and PSA Crypto constants. */
public final class MbedTLSAlgorithmNames {

    public static final Map<String, String> DIGESTS = digestMappings();
    public static final Map<String, String> HASH_SUFFIXES = hashSuffixMappings();
    public static final Map<String, String> CIPHERS = cipherMappings();
    public static final Map<String, String> MACS = macMappings();
    public static final Map<String, String> SIGNATURES = signatureMappings();
    public static final Map<String, String> KEY_AGREEMENTS = keyAgreementMappings();
    public static final Map<String, String> TLS_VERSIONS = tlsVersionMappings();
    public static final String DEFAULT_TLS_VERSION = "1.3";
    public static final List<String> DEFAULT_TLS_CIPHER_SUITES = defaultTlsCipherSuites();
    public static final List<String> DEFAULT_TLS_GROUPS = defaultTlsGroups();
    public static final List<String> DEFAULT_TLS_SIGNATURE_SCHEMES = defaultTlsSignatureSchemes();
    private static final String MBEDTLS_TLS_PREFIX = "MBEDTLS_TLS_";
    private static final String MBEDTLS_TLS13_PREFIX = "MBEDTLS_TLS1_3_";
    private static final String MBEDTLS_TLS_GROUP_PREFIX = "MBEDTLS_SSL_IANA_TLS_GROUP_";
    private static final String MBEDTLS_TLS_SIG_PREFIX = "MBEDTLS_TLS_SIG_";
    private static final String MBEDTLS_TLS13_SIG_PREFIX = "MBEDTLS_TLS1_3_SIG_";
    private static final String MBEDTLS_TLS_IANA_SIG_PREFIX = "MBEDTLS_SSL_IANA_TLS_SIG_";

    private MbedTLSAlgorithmNames() {
        // utility class
    }

    @Nonnull
    public static Optional<String> hashSuffixFor(@Nonnull String identifier) {
        return Optional.ofNullable(HASH_SUFFIXES.get(identifier));
    }

    @Nonnull
    public static Optional<String> tlsCipherSuiteFor(@Nonnull String identifier) {
        if (identifier.startsWith(MBEDTLS_TLS13_PREFIX)) {
            return Optional.of("TLS_" + identifier.substring(MBEDTLS_TLS13_PREFIX.length()));
        }
        if (identifier.startsWith(MBEDTLS_TLS_PREFIX)) {
            return Optional.of("TLS_" + identifier.substring(MBEDTLS_TLS_PREFIX.length()));
        }
        return Optional.empty();
    }

    @Nonnull
    public static Optional<String> tlsGroupFor(@Nonnull String identifier) {
        if (identifier.startsWith(MBEDTLS_TLS_GROUP_PREFIX)) {
            return Optional.of(
                    toTlsRegistryName(identifier.substring(MBEDTLS_TLS_GROUP_PREFIX.length())));
        }
        return switch (identifier) {
            case "MBEDTLS_ECP_DP_SECP192R1" -> Optional.of("secp192r1");
            case "MBEDTLS_ECP_DP_SECP224R1" -> Optional.of("secp224r1");
            case "MBEDTLS_ECP_DP_SECP256R1" -> Optional.of("secp256r1");
            case "MBEDTLS_ECP_DP_SECP384R1" -> Optional.of("secp384r1");
            case "MBEDTLS_ECP_DP_SECP521R1" -> Optional.of("secp521r1");
            case "MBEDTLS_ECP_DP_SECP192K1" -> Optional.of("secp192k1");
            case "MBEDTLS_ECP_DP_SECP224K1" -> Optional.of("secp224k1");
            case "MBEDTLS_ECP_DP_SECP256K1" -> Optional.of("secp256k1");
            case "MBEDTLS_ECP_DP_BP256R1" -> Optional.of("brainpoolP256r1");
            case "MBEDTLS_ECP_DP_BP384R1" -> Optional.of("brainpoolP384r1");
            case "MBEDTLS_ECP_DP_BP512R1" -> Optional.of("brainpoolP512r1");
            case "MBEDTLS_ECP_DP_CURVE25519" -> Optional.of("x25519");
            case "MBEDTLS_ECP_DP_CURVE448" -> Optional.of("x448");
            default -> Optional.empty();
        };
    }

    @Nonnull
    public static Optional<String> tlsSignatureSchemeFor(@Nonnull String identifier) {
        if (identifier.startsWith(MBEDTLS_TLS_IANA_SIG_PREFIX)) {
            return Optional.of(
                    toTlsRegistryName(identifier.substring(MBEDTLS_TLS_IANA_SIG_PREFIX.length())));
        }
        if (identifier.startsWith(MBEDTLS_TLS13_SIG_PREFIX)) {
            return Optional.of(
                    toTlsRegistryName(identifier.substring(MBEDTLS_TLS13_SIG_PREFIX.length())));
        }
        if (identifier.startsWith(MBEDTLS_TLS_SIG_PREFIX)) {
            return Optional.of(
                    toTlsRegistryName(identifier.substring(MBEDTLS_TLS_SIG_PREFIX.length())));
        }
        return Optional.empty();
    }

    @Nonnull
    private static String toTlsRegistryName(@Nonnull String suffix) {
        return suffix.toLowerCase().replace("with_", "");
    }

    @Nonnull
    private static Map<String, String> digestMappings() {
        Map<String, String> mappings = new LinkedHashMap<>();
        mappings.put("MBEDTLS_MD_MD5", "MD5");
        mappings.put("MBEDTLS_MD_RIPEMD160", "RIPEMD160");
        mappings.put("MBEDTLS_MD_SHA1", "SHA-1");
        mappings.put("MBEDTLS_MD_SHA224", "SHA-224");
        mappings.put("MBEDTLS_MD_SHA256", "SHA-256");
        mappings.put("MBEDTLS_MD_SHA384", "SHA-384");
        mappings.put("MBEDTLS_MD_SHA512", "SHA-512");
        mappings.put("MBEDTLS_MD_SHA3_224", "SHA3-224");
        mappings.put("MBEDTLS_MD_SHA3_256", "SHA3-256");
        mappings.put("MBEDTLS_MD_SHA3_384", "SHA3-384");
        mappings.put("MBEDTLS_MD_SHA3_512", "SHA3-512");
        mappings.put("PSA_ALG_MD5", "MD5");
        mappings.put("PSA_ALG_RIPEMD160", "RIPEMD160");
        mappings.put("PSA_ALG_SHA_1", "SHA-1");
        mappings.put("PSA_ALG_SHA_224", "SHA-224");
        mappings.put("PSA_ALG_SHA_256", "SHA-256");
        mappings.put("PSA_ALG_SHA_384", "SHA-384");
        mappings.put("PSA_ALG_SHA_512", "SHA-512");
        mappings.put("PSA_ALG_SHA_512_224", "SHA-512/224");
        mappings.put("PSA_ALG_SHA_512_256", "SHA-512/256");
        mappings.put("PSA_ALG_SHA3_224", "SHA3-224");
        mappings.put("PSA_ALG_SHA3_256", "SHA3-256");
        mappings.put("PSA_ALG_SHA3_384", "SHA3-384");
        mappings.put("PSA_ALG_SHA3_512", "SHA3-512");
        mappings.put("PSA_ALG_SHAKE256_512", "SHAKE256");
        return mappings;
    }

    @Nonnull
    private static Map<String, String> hashSuffixMappings() {
        Map<String, String> mappings = new LinkedHashMap<>();
        mappings.put("MBEDTLS_MD_MD5", "MD5");
        mappings.put("MBEDTLS_MD_RIPEMD160", "RIPEMD160");
        mappings.put("MBEDTLS_MD_SHA1", "SHA1");
        mappings.put("MBEDTLS_MD_SHA224", "SHA224");
        mappings.put("MBEDTLS_MD_SHA256", "SHA256");
        mappings.put("MBEDTLS_MD_SHA384", "SHA384");
        mappings.put("MBEDTLS_MD_SHA512", "SHA512");
        mappings.put("MBEDTLS_MD_SHA3_224", "SHA3-224");
        mappings.put("MBEDTLS_MD_SHA3_256", "SHA3-256");
        mappings.put("MBEDTLS_MD_SHA3_384", "SHA3-384");
        mappings.put("MBEDTLS_MD_SHA3_512", "SHA3-512");
        mappings.put("PSA_ALG_MD5", "MD5");
        mappings.put("PSA_ALG_RIPEMD160", "RIPEMD160");
        mappings.put("PSA_ALG_SHA_1", "SHA1");
        mappings.put("PSA_ALG_SHA_224", "SHA224");
        mappings.put("PSA_ALG_SHA_256", "SHA256");
        mappings.put("PSA_ALG_SHA_384", "SHA384");
        mappings.put("PSA_ALG_SHA_512", "SHA512");
        mappings.put("PSA_ALG_SHA_512_224", "SHA512/224");
        mappings.put("PSA_ALG_SHA_512_256", "SHA512/256");
        mappings.put("PSA_ALG_SHA3_224", "SHA3-224");
        mappings.put("PSA_ALG_SHA3_256", "SHA3-256");
        mappings.put("PSA_ALG_SHA3_384", "SHA3-384");
        mappings.put("PSA_ALG_SHA3_512", "SHA3-512");
        return mappings;
    }

    @Nonnull
    private static Map<String, String> cipherMappings() {
        Map<String, String> mappings = new LinkedHashMap<>();
        mappings.put("MBEDTLS_CIPHER_AES_128_CBC", "AES-128-CBC");
        mappings.put("MBEDTLS_CIPHER_AES_192_CBC", "AES-192-CBC");
        mappings.put("MBEDTLS_CIPHER_AES_256_CBC", "AES-256-CBC");
        mappings.put("MBEDTLS_CIPHER_AES_128_CCM", "AES-128-CCM");
        mappings.put("MBEDTLS_CIPHER_AES_192_CCM", "AES-192-CCM");
        mappings.put("MBEDTLS_CIPHER_AES_256_CCM", "AES-256-CCM");
        mappings.put("MBEDTLS_CIPHER_AES_128_GCM", "AES-128-GCM");
        mappings.put("MBEDTLS_CIPHER_AES_192_GCM", "AES-192-GCM");
        mappings.put("MBEDTLS_CIPHER_AES_256_GCM", "AES-256-GCM");
        mappings.put("MBEDTLS_CIPHER_AES_128_CTR", "AES-128-CTR");
        mappings.put("MBEDTLS_CIPHER_AES_192_CTR", "AES-192-CTR");
        mappings.put("MBEDTLS_CIPHER_AES_256_CTR", "AES-256-CTR");
        mappings.put("MBEDTLS_CIPHER_AES_128_CFB128", "AES-128-CFB128");
        mappings.put("MBEDTLS_CIPHER_AES_192_CFB128", "AES-192-CFB128");
        mappings.put("MBEDTLS_CIPHER_AES_256_CFB128", "AES-256-CFB128");
        mappings.put("MBEDTLS_CIPHER_AES_128_ECB", "AES-128-ECB");
        mappings.put("MBEDTLS_CIPHER_AES_192_ECB", "AES-192-ECB");
        mappings.put("MBEDTLS_CIPHER_AES_256_ECB", "AES-256-ECB");
        mappings.put("MBEDTLS_CIPHER_DES_ECB", "DES-ECB");
        mappings.put("MBEDTLS_CIPHER_DES_CBC", "DES-CBC");
        mappings.put("MBEDTLS_CIPHER_DES_EDE_ECB", "DESede-ECB");
        mappings.put("MBEDTLS_CIPHER_DES_EDE_CBC", "DESede-CBC");
        mappings.put("MBEDTLS_CIPHER_DES_EDE3_ECB", "DESede3-ECB");
        mappings.put("MBEDTLS_CIPHER_DES_EDE3_CBC", "DESede3-CBC");
        mappings.put("MBEDTLS_CIPHER_CAMELLIA_128_CBC", "CAMELLIA-128-CBC");
        mappings.put("MBEDTLS_CIPHER_CAMELLIA_192_CBC", "CAMELLIA-192-CBC");
        mappings.put("MBEDTLS_CIPHER_CAMELLIA_256_CBC", "CAMELLIA-256-CBC");
        mappings.put("MBEDTLS_CIPHER_CAMELLIA_128_GCM", "CAMELLIA-128-GCM");
        mappings.put("MBEDTLS_CIPHER_CAMELLIA_192_GCM", "CAMELLIA-192-GCM");
        mappings.put("MBEDTLS_CIPHER_CAMELLIA_256_GCM", "CAMELLIA-256-GCM");
        mappings.put("MBEDTLS_CIPHER_ARIA_128_CBC", "ARIA-128-CBC");
        mappings.put("MBEDTLS_CIPHER_ARIA_256_CBC", "ARIA-256-CBC");
        mappings.put("MBEDTLS_CIPHER_ARIA_128_GCM", "ARIA-128-GCM");
        mappings.put("MBEDTLS_CIPHER_ARIA_256_GCM", "ARIA-256-GCM");
        mappings.put("MBEDTLS_CIPHER_CHACHA20_POLY1305", "CHACHA20-POLY1305");
        mappings.put("PSA_ALG_CHACHA20_POLY1305", "CHACHA20-POLY1305");
        return mappings;
    }

    @Nonnull
    private static Map<String, String> macMappings() {
        Map<String, String> mappings = new LinkedHashMap<>();
        mappings.put("PSA_ALG_CMAC", "CMAC");
        mappings.put("PSA_ALG_CBC_MAC", "CBC-MAC");
        return mappings;
    }

    @Nonnull
    private static Map<String, String> signatureMappings() {
        Map<String, String> mappings = new LinkedHashMap<>();
        mappings.put("PSA_ALG_PURE_EDDSA", "EDDSA");
        mappings.put("PSA_ALG_ED25519PH", "ED25519");
        mappings.put("PSA_ALG_ED448PH", "ED448");
        mappings.put("PSA_ALG_RSA_PKCS1V15_SIGN_RAW", "RSA");
        return mappings;
    }

    @Nonnull
    private static Map<String, String> keyAgreementMappings() {
        Map<String, String> mappings = new LinkedHashMap<>();
        mappings.put("PSA_ALG_ECDH", "ECDH");
        mappings.put("PSA_ALG_FFDH", "DH");
        return mappings;
    }

    @Nonnull
    private static Map<String, String> tlsVersionMappings() {
        Map<String, String> mappings = new LinkedHashMap<>();
        mappings.put("MBEDTLS_SSL_VERSION_TLS1_2", "TLSv1.2");
        mappings.put("MBEDTLS_SSL_VERSION_TLS1_3", "TLSv1.3");
        return mappings;
    }

    @Nonnull
    private static List<String> defaultTlsCipherSuites() {
        return List.of(
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_128_CCM_SHA256",
                "TLS_AES_128_CCM_8_SHA256",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
                "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
                "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
                "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
                "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
                "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
                "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
                "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
                "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
                "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
                "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
                "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
                "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
                "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
                "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384",
                "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
                "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
                "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
                "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256",
                "TLS_ECJPAKE_WITH_AES_128_CCM_8",
                "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_PSK_WITH_AES_256_GCM_SHA384",
                "TLS_PSK_WITH_AES_256_CCM",
                "TLS_PSK_WITH_AES_256_CBC_SHA384",
                "TLS_PSK_WITH_AES_256_CBC_SHA",
                "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384",
                "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384",
                "TLS_PSK_WITH_AES_256_CCM_8",
                "TLS_PSK_WITH_ARIA_256_GCM_SHA384",
                "TLS_PSK_WITH_ARIA_256_CBC_SHA384",
                "TLS_PSK_WITH_AES_128_GCM_SHA256",
                "TLS_PSK_WITH_AES_128_CCM",
                "TLS_PSK_WITH_AES_128_CBC_SHA256",
                "TLS_PSK_WITH_AES_128_CBC_SHA",
                "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256",
                "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256",
                "TLS_PSK_WITH_AES_128_CCM_8",
                "TLS_PSK_WITH_ARIA_128_GCM_SHA256",
                "TLS_PSK_WITH_ARIA_128_CBC_SHA256");
    }

    @Nonnull
    private static List<String> defaultTlsGroups() {
        return List.of("x25519", "secp256r1", "secp384r1", "x448", "secp521r1", "ffdhe2048");
    }

    @Nonnull
    private static List<String> defaultTlsSignatureSchemes() {
        return List.of(
                "ecdsa_secp256r1_sha256",
                "ecdsa_secp384r1_sha384",
                "ecdsa_secp521r1_sha512",
                "rsa_pss_rsae_sha512",
                "rsa_pss_rsae_sha384",
                "rsa_pss_rsae_sha256",
                "ed25519",
                "ed448",
                "rsa_pkcs1_sha512",
                "rsa_pkcs1_sha384",
                "rsa_pkcs1_sha256");
    }
}
