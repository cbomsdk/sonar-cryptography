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

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/** Canonical algorithm-name mappings for openHiTLS public constants. */
public final class OpenHiTLSAlgorithmNames {

    public static final Map<String, String> DIGESTS = digestMappings();
    public static final Map<String, String> CIPHERS = cipherMappings();
    public static final Map<String, String> MACS = macMappings();
    public static final Map<String, String> KDFS = kdfMappings();
    public static final Map<String, String> SIGNATURES = signatureMappings();
    public static final Map<String, String> KEY_AGREEMENTS = keyAgreementMappings();
    public static final Map<String, String> RANDS = randMappings();
    public static final Map<String, String> TLS_VERSIONS = tlsVersionMappings();
    public static final List<String> DEFAULT_TLS12_CIPHER_SUITES = defaultTls12CipherSuites();
    public static final List<String> DEFAULT_TLS13_CIPHER_SUITES = defaultTls13CipherSuites();
    public static final List<String> DEFAULT_TLS_CIPHER_SUITES =
            Stream.concat(
                            DEFAULT_TLS13_CIPHER_SUITES.stream(),
                            DEFAULT_TLS12_CIPHER_SUITES.stream())
                    .distinct()
                    .toList();
    public static final List<String> DEFAULT_TLS_GROUPS = defaultTlsGroups();
    public static final List<String> DEFAULT_TLS_SIGNATURE_SCHEMES = defaultTlsSignatureSchemes();

    private static final String HITLS_CIPHER_SUITE_PREFIX = "HITLS_";
    private static final String HITLS_GROUP_PREFIX = "HITLS_EC_GROUP_";
    private static final String HITLS_FFDHE_PREFIX = "HITLS_FF_DHE_";
    private static final String HITLS_HYBRID_PREFIX = "HITLS_HYBRID_";
    private static final String HITLS_SIGNATURE_SCHEME_PREFIX = "CERT_SIG_SCHEME_";

    private OpenHiTLSAlgorithmNames() {
        // utility class
    }

    @Nonnull
    public static Optional<String> tlsCipherSuiteFor(@Nonnull String identifier) {
        if (!identifier.startsWith(HITLS_CIPHER_SUITE_PREFIX)) {
            return Optional.empty();
        }
        String suffix = identifier.substring(HITLS_CIPHER_SUITE_PREFIX.length());
        if (suffix.startsWith("ECDHE_SM4_") || suffix.startsWith("ECC_SM4_")) {
            return Optional.empty();
        }
        return Optional.of("TLS_" + suffix);
    }

    @Nonnull
    public static Optional<String> tlsGroupFor(@Nonnull String identifier) {
        if (identifier.startsWith(HITLS_FFDHE_PREFIX)) {
            return Optional.of("ffdhe" + identifier.substring(HITLS_FFDHE_PREFIX.length()));
        }
        if (identifier.startsWith(HITLS_HYBRID_PREFIX)) {
            return hybridGroupFor(identifier.substring(HITLS_HYBRID_PREFIX.length()));
        }
        if (identifier.startsWith(HITLS_GROUP_PREFIX)) {
            return switch (identifier.substring(HITLS_GROUP_PREFIX.length())) {
                case "SECP256R1" -> Optional.of("secp256r1");
                case "SECP384R1" -> Optional.of("secp384r1");
                case "SECP521R1" -> Optional.of("secp521r1");
                case "BRAINPOOLP256R1" -> Optional.of("brainpoolP256r1");
                case "BRAINPOOLP384R1" -> Optional.of("brainpoolP384r1");
                case "BRAINPOOLP512R1" -> Optional.of("brainpoolP512r1");
                case "CURVE25519" -> Optional.of("x25519");
                case "SM2" -> Optional.of("curveSM2");
                default -> Optional.empty();
            };
        }
        return normalizedGroupName(identifier);
    }

    @Nonnull
    public static Stream<String> tlsGroupsFromGroupList(@Nonnull String groupList) {
        return Arrays.stream(groupList.split("[:/]"))
                .map(String::trim)
                .map(OpenHiTLSAlgorithmNames::stripGroupModifiers)
                .map(OpenHiTLSAlgorithmNames::tlsGroupFor)
                .flatMap(Optional::stream);
    }

    @Nonnull
    public static Optional<String> tlsSignatureSchemeFor(@Nonnull String identifier) {
        if (!identifier.startsWith(HITLS_SIGNATURE_SCHEME_PREFIX)) {
            return Optional.empty();
        }
        return Optional.of(
                identifier
                        .substring(HITLS_SIGNATURE_SCHEME_PREFIX.length())
                        .toLowerCase(Locale.ROOT));
    }

    @Nonnull
    private static Optional<String> hybridGroupFor(@Nonnull String suffix) {
        return switch (suffix) {
            case "X25519_MLKEM768" -> Optional.of("X25519MLKEM768");
            case "ECDH_NISTP256_MLKEM768" -> Optional.of("SecP256r1MLKEM768");
            case "ECDH_NISTP384_MLKEM1024" -> Optional.of("SecP384r1MLKEM1024");
            default -> Optional.empty();
        };
    }

    @Nonnull
    private static Optional<String> normalizedGroupName(@Nonnull String identifier) {
        return switch (identifier) {
            case "x25519", "X25519" -> Optional.of("x25519");
            case "secp256r1", "secp384r1", "secp521r1" -> Optional.of(identifier);
            case "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1" -> Optional.of(identifier);
            case "ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192" ->
                    Optional.of(identifier);
            case "sm2", "curveSM2", "curveSm2" -> Optional.of("curveSM2");
            case "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024" ->
                    Optional.of(identifier);
            default -> Optional.empty();
        };
    }

    @Nonnull
    private static String stripGroupModifiers(@Nonnull String groupName) {
        String stripped = groupName;
        while (stripped.startsWith("?") || stripped.startsWith("*")) {
            stripped = stripped.substring(1);
        }
        return stripped;
    }

    @Nonnull
    private static Map<String, String> digestMappings() {
        Map<String, String> mappings = new LinkedHashMap<>();
        mappings.put("CRYPT_MD_MD5", "MD5");
        mappings.put("CRYPT_MD_SHA1", "SHA-1");
        mappings.put("CRYPT_MD_SHA224", "SHA-224");
        mappings.put("CRYPT_MD_SHA256", "SHA-256");
        mappings.put("CRYPT_MD_SHA384", "SHA-384");
        mappings.put("CRYPT_MD_SHA512", "SHA-512");
        mappings.put("CRYPT_MD_SHA3_224", "SHA3-224");
        mappings.put("CRYPT_MD_SHA3_256", "SHA3-256");
        mappings.put("CRYPT_MD_SHA3_384", "SHA3-384");
        mappings.put("CRYPT_MD_SHA3_512", "SHA3-512");
        mappings.put("CRYPT_MD_SHAKE128", "SHAKE128");
        mappings.put("CRYPT_MD_SHAKE256", "SHAKE256");
        mappings.put("CRYPT_MD_SM3", "SM3");
        mappings.put("CRYPT_MD_SHA256_MB", "SHA-256");
        return mappings;
    }

    @Nonnull
    private static Map<String, String> cipherMappings() {
        Map<String, String> mappings = new LinkedHashMap<>();
        aesMappings(mappings, "128");
        aesMappings(mappings, "192");
        aesMappings(mappings, "256");
        mappings.put("CRYPT_CIPHER_CHACHA20_POLY1305", "CHACHA20-POLY1305");
        mappings.put("CRYPT_CIPHER_SM4_XTS", "SM4-XTS");
        mappings.put("CRYPT_CIPHER_SM4_CBC", "SM4-CBC");
        mappings.put("CRYPT_CIPHER_SM4_ECB", "SM4-ECB");
        mappings.put("CRYPT_CIPHER_SM4_CTR", "SM4-CTR");
        mappings.put("CRYPT_CIPHER_SM4_GCM", "SM4-GCM");
        mappings.put("CRYPT_CIPHER_SM4_CFB", "SM4-CFB");
        mappings.put("CRYPT_CIPHER_SM4_OFB", "SM4-OFB");
        mappings.put("CRYPT_CIPHER_SM4_CCM", "SM4-CCM");
        return mappings;
    }

    private static void aesMappings(@Nonnull Map<String, String> mappings, @Nonnull String bits) {
        mappings.put("CRYPT_CIPHER_AES" + bits + "_CBC", "AES-" + bits + "-CBC");
        mappings.put("CRYPT_CIPHER_AES" + bits + "_CTR", "AES-" + bits + "-CTR");
        mappings.put("CRYPT_CIPHER_AES" + bits + "_ECB", "AES-" + bits + "-ECB");
        mappings.put("CRYPT_CIPHER_AES" + bits + "_CCM", "AES-" + bits + "-CCM");
        mappings.put("CRYPT_CIPHER_AES" + bits + "_GCM", "AES-" + bits + "-GCM");
        mappings.put("CRYPT_CIPHER_AES" + bits + "_CFB", "AES-" + bits + "-CFB");
        mappings.put("CRYPT_CIPHER_AES" + bits + "_OFB", "AES-" + bits + "-OFB");
        mappings.put("CRYPT_CIPHER_AES" + bits + "_WRAP_NOPAD", "AES-" + bits + "-WRAP");
        mappings.put("CRYPT_CIPHER_AES" + bits + "_WRAP_PAD", "AES-" + bits + "-WRAP-PAD");
    }

    @Nonnull
    private static Map<String, String> macMappings() {
        Map<String, String> mappings = new LinkedHashMap<>();
        mappings.put("CRYPT_MAC_HMAC_MD5", "HMAC-MD5");
        mappings.put("CRYPT_MAC_HMAC_SHA1", "HMAC-SHA1");
        mappings.put("CRYPT_MAC_HMAC_SHA224", "HMAC-SHA224");
        mappings.put("CRYPT_MAC_HMAC_SHA256", "HMAC-SHA256");
        mappings.put("CRYPT_MAC_HMAC_SHA384", "HMAC-SHA384");
        mappings.put("CRYPT_MAC_HMAC_SHA512", "HMAC-SHA512");
        mappings.put("CRYPT_MAC_HMAC_SHA3_224", "HMAC-SHA3-224");
        mappings.put("CRYPT_MAC_HMAC_SHA3_256", "HMAC-SHA3-256");
        mappings.put("CRYPT_MAC_HMAC_SHA3_384", "HMAC-SHA3-384");
        mappings.put("CRYPT_MAC_HMAC_SHA3_512", "HMAC-SHA3-512");
        mappings.put("CRYPT_MAC_HMAC_SM3", "HMAC-SM3");
        mappings.put("CRYPT_MAC_CMAC_AES128", "CMAC-AES-128");
        mappings.put("CRYPT_MAC_CMAC_AES192", "CMAC-AES-192");
        mappings.put("CRYPT_MAC_CMAC_AES256", "CMAC-AES-256");
        mappings.put("CRYPT_MAC_CMAC_SM4", "CMAC-SM4");
        mappings.put("CRYPT_MAC_CBC_MAC_SM4", "CBC-MAC");
        mappings.put("CRYPT_MAC_GMAC_AES128", "GMAC-AES-128");
        mappings.put("CRYPT_MAC_GMAC_AES192", "GMAC-AES-192");
        mappings.put("CRYPT_MAC_GMAC_AES256", "GMAC-AES-256");
        mappings.put("CRYPT_MAC_SIPHASH64", "SIPHASH-2-4");
        mappings.put("CRYPT_MAC_SIPHASH128", "SIPHASH-2-4");
        return mappings;
    }

    @Nonnull
    private static Map<String, String> kdfMappings() {
        Map<String, String> mappings = new LinkedHashMap<>();
        mappings.put("CRYPT_KDF_SCRYPT", "SCRYPT");
        mappings.put("CRYPT_KDF_PBKDF2", "PBKDF2");
        mappings.put("CRYPT_KDF_KDFTLS12", "TLS1-PRF");
        mappings.put("CRYPT_KDF_HKDF", "HKDF");
        mappings.put("CRYPT_HKDF_SHA256", "HKDF-SHA256");
        mappings.put("CRYPT_HKDF_SHA512", "HKDF-SHA512");
        return mappings;
    }

    @Nonnull
    private static Map<String, String> signatureMappings() {
        Map<String, String> mappings = new LinkedHashMap<>();
        mappings.put("CRYPT_PKEY_DSA", "DSA");
        mappings.put("CRYPT_PKEY_ED25519", "ED25519");
        mappings.put("CRYPT_PKEY_RSA", "RSA");
        mappings.put("CRYPT_PKEY_ECDSA", "ECDSA");
        mappings.put("CRYPT_PKEY_SM2", "SM2");
        return mappings;
    }

    @Nonnull
    private static Map<String, String> keyAgreementMappings() {
        Map<String, String> mappings = new LinkedHashMap<>();
        mappings.put("CRYPT_PKEY_X25519", "X25519");
        mappings.put("CRYPT_PKEY_DH", "DH");
        mappings.put("CRYPT_PKEY_ECDH", "ECDH");
        mappings.put("CRYPT_PKEY_SM2", "SM2");
        return mappings;
    }

    @Nonnull
    private static Map<String, String> randMappings() {
        Map<String, String> mappings = new LinkedHashMap<>();
        mappings.put("CRYPT_RAND_SHA1", "HASH-DRBG-SHA1");
        mappings.put("CRYPT_RAND_SHA224", "HASH-DRBG-SHA224");
        mappings.put("CRYPT_RAND_SHA256", "HASH-DRBG-SHA256");
        mappings.put("CRYPT_RAND_SHA384", "HASH-DRBG-SHA384");
        mappings.put("CRYPT_RAND_SHA512", "HASH-DRBG-SHA512");
        mappings.put("CRYPT_RAND_HMAC_SHA1", "HMAC-DRBG-SHA1");
        mappings.put("CRYPT_RAND_HMAC_SHA224", "HMAC-DRBG-SHA224");
        mappings.put("CRYPT_RAND_HMAC_SHA256", "HMAC-DRBG-SHA256");
        mappings.put("CRYPT_RAND_HMAC_SHA384", "HMAC-DRBG-SHA384");
        mappings.put("CRYPT_RAND_HMAC_SHA512", "HMAC-DRBG-SHA512");
        mappings.put("CRYPT_RAND_AES128_CTR", "CTR-DRBG-AES128");
        mappings.put("CRYPT_RAND_AES192_CTR", "CTR-DRBG-AES192");
        mappings.put("CRYPT_RAND_AES256_CTR", "CTR-DRBG-AES256");
        mappings.put("CRYPT_RAND_AES128_CTR_DF", "CTR-DRBG-AES128");
        mappings.put("CRYPT_RAND_AES192_CTR_DF", "CTR-DRBG-AES192");
        mappings.put("CRYPT_RAND_AES256_CTR_DF", "CTR-DRBG-AES256");
        mappings.put("CRYPT_RAND_SM3", "RAND");
        mappings.put("CRYPT_RAND_SM4_CTR_DF", "RAND");
        return mappings;
    }

    @Nonnull
    private static Map<String, String> tlsVersionMappings() {
        Map<String, String> mappings = new LinkedHashMap<>();
        mappings.put("HITLS_VERSION_TLS10", "TLSv1.0");
        mappings.put("HITLS_VERSION_TLS11", "TLSv1.1");
        mappings.put("HITLS_VERSION_TLS12", "TLSv1.2");
        mappings.put("HITLS_VERSION_TLS13", "TLSv1.3");
        mappings.put("HITLS_TLS_ANY_VERSION", "TLS");
        return mappings;
    }

    @Nonnull
    private static List<String> defaultTls13CipherSuites() {
        return List.of(
                "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256");
    }

    @Nonnull
    private static List<String> defaultTls12CipherSuites() {
        return List.of(
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
                "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
                "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
                "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
                "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                "TLS_DHE_RSA_WITH_AES_128_CCM",
                "TLS_DHE_RSA_WITH_AES_256_CCM",
                "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
                "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
                "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
                "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
                "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
                "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
                "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
                "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
                "TLS_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_PSK_WITH_AES_256_GCM_SHA384",
                "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
                "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
                "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
                "TLS_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_PSK_WITH_AES_128_GCM_SHA256",
                "TLS_PSK_WITH_AES_256_CCM",
                "TLS_RSA_WITH_AES_256_CBC_SHA256",
                "TLS_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",
                "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
                "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
                "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384",
                "TLS_DHE_PSK_WITH_AES_128_CCM",
                "TLS_DHE_PSK_WITH_AES_256_CCM",
                "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
                "TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
                "TLS_DHE_PSK_WITH_AES_256_CBC_SHA",
                "TLS_RSA_WITH_AES_256_CBC_SHA",
                "TLS_PSK_WITH_AES_256_CBC_SHA384",
                "TLS_PSK_WITH_AES_256_CBC_SHA",
                "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
                "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
                "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
                "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
                "TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
                "TLS_DHE_PSK_WITH_AES_128_CBC_SHA",
                "TLS_RSA_WITH_AES_128_CBC_SHA",
                "TLS_PSK_WITH_AES_128_CBC_SHA256",
                "TLS_PSK_WITH_AES_128_CBC_SHA");
    }

    @Nonnull
    private static List<String> defaultTlsGroups() {
        return List.of(
                "X25519MLKEM768",
                "x25519",
                "secp256r1",
                "secp384r1",
                "secp521r1",
                "curveSM2",
                "ffdhe2048",
                "ffdhe3072",
                "ffdhe4096",
                "ffdhe6144",
                "ffdhe8192");
    }

    @Nonnull
    private static List<String> defaultTlsSignatureSchemes() {
        return List.of(
                "ecdsa_secp256r1_sha256",
                "ecdsa_secp384r1_sha384",
                "ecdsa_secp521r1_sha512",
                "ed25519",
                "sm2_sm3",
                "rsa_pss_pss_sha256",
                "rsa_pss_pss_sha384",
                "rsa_pss_pss_sha512",
                "rsa_pss_rsae_sha256",
                "rsa_pss_rsae_sha384",
                "rsa_pss_rsae_sha512",
                "rsa_pkcs1_sha256",
                "rsa_pkcs1_sha384",
                "rsa_pkcs1_sha512",
                "ecdsa_sha224",
                "ecdsa_sha1",
                "rsa_pkcs1_sha224",
                "rsa_pkcs1_sha1",
                "dsa_sha224",
                "dsa_sha256",
                "dsa_sha384",
                "dsa_sha512",
                "dsa_sha1");
    }
}
