static const int configured_ciphersuites[] = {
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS1_3_AES_256_GCM_SHA384,
    0,
};

void mbedtls_detection_rules() {
    static const mbedtls_ecp_group_id configured_groups[] = {
        MBEDTLS_ECP_DP_SECP384R1,
        MBEDTLS_ECP_DP_CURVE25519,
        MBEDTLS_ECP_DP_NONE,
    };
    static const uint16_t configured_signature_schemes[] = {
        MBEDTLS_TLS_SIG_RSA_PSS_RSAE_SHA256,
        MBEDTLS_TLS_SIG_ECDSA_SECP384R1_SHA384,
        0,
    };

    mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    psa_hash_compute(PSA_ALG_SHA_384, input, input_len, hash, hash_size, hash_len);
    PSA_ALG_HMAC(PSA_ALG_SHA_256);
    PSA_ALG_HKDF(PSA_ALG_SHA_256);
    mbedtls_pk_sign_ext(
            MBEDTLS_PK_SIGALG_RSA_PSS, pk, MBEDTLS_MD_SHA256, hash, hash_len, sig, sig_size,
            sig_len);
    PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    psa_raw_key_agreement(PSA_ALG_ECDH, private_key, peer_key, peer_key_len, output, output_size,
            output_len);
    mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM);
    mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_DES_CBC);
    mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CFB128);
    mbedtls_md_hmac_starts(ctx, key, key_len);
    psa_aead_encrypt(key, PSA_ALG_CHACHA20_POLY1305, nonce, nonce_len, ad, ad_len, input,
            input_len, output, output_size, output_len);
    psa_generate_random(output, output_size);
    mbedtls_ssl_conf_min_tls_version(conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_ciphersuites(conf, MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
    mbedtls_ssl_conf_ciphersuites(conf, MBEDTLS_TLS1_3_AES_128_GCM_SHA256);
    mbedtls_ssl_conf_ciphersuites(conf, configured_ciphersuites);
    mbedtls_ssl_conf_groups(conf, MBEDTLS_ECP_DP_CURVE25519);
    mbedtls_ssl_conf_groups(conf, configured_groups);
    mbedtls_ssl_conf_sig_algs(conf, MBEDTLS_TLS_SIG_ECDSA_SECP256R1_SHA256);
    mbedtls_ssl_conf_sig_algs(conf, configured_signature_schemes);
    mbedtls_ssl_config_defaults(conf, endpoint, MBEDTLS_SSL_TRANSPORT_STREAM,
            MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_setup(ssl, conf);
}
