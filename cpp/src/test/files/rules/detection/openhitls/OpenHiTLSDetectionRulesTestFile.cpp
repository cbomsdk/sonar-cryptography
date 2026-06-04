static const uint16_t configured_ciphersuites[] = {
    HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    HITLS_AES_128_GCM_SHA256,
};

void openhitls_detection_rules() {
    static const uint16_t configured_groups[] = {
        HITLS_EC_GROUP_SECP384R1,
        HITLS_HYBRID_X25519_MLKEM768,
    };
    static const uint16_t configured_signature_schemes[] = {
        CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256,
        CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384,
    };

    CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256);
    CRYPT_EAL_ProviderMdNewCtx(libCtx, CRYPT_MD_SHA384, attrName);
    CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_AES256_GCM);
    CRYPT_EAL_ProviderCipherNewCtx(libCtx, CRYPT_CIPHER_SM4_GCM, attrName);
    CRYPT_EAL_MacNewCtx(CRYPT_MAC_HMAC_SM3);
    CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    CRYPT_EAL_KdfNewCtx(CRYPT_KDF_PBKDF2);
    CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDH);
    CRYPT_EAL_RandInit(CRYPT_RAND_AES256_CTR_DF, seedMeth, seedCtx, nullCallback, 0);
    CRYPT_EAL_Randbytes(output, output_size);

    HITLS_CFG_SetMinProtoVersion(config, HITLS_VERSION_TLS12);
    HITLS_CFG_NewTLS12Config();
    HITLS_CFG_NewTLS13Config();
    HITLS_CFG_SetCipherSuites(config, HITLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, 1);
    HITLS_CFG_SetCipherSuites(config, configured_ciphersuites, 2);
    HITLS_CFG_SetGroups(config, HITLS_EC_GROUP_CURVE25519, 1);
    HITLS_CFG_SetGroups(config, configured_groups, 2);
    HITLS_CFG_SetGroupList(
            config, "HITLS_EC_GROUP_SECP256R1:HITLS_EC_GROUP_SECP384R1", 0);
    HITLS_CFG_SetSignature(config, CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256, 1);
    HITLS_CFG_SetSignature(config, configured_signature_schemes, 2);
    HITLS_New(config);
    HITLS_Connect(ctx);
}
