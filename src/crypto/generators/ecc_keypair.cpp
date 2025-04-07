// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "ecc_keypair.h"
#include <openssl/engine.h>
#include "util/util.h"

using namespace cyber;

static constexpr auto engine_id = "cyber_security";

std::string EccKeyPair::GetAlgorithmName() {
    const char *pcName;
    if (pkey_ == nullptr) {
        return "NONE";
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000
    pcName = EVP_PKEY_get0_type_name(pkey_);
#else
    int id = EVP_PKEY_id(pkey_);
    switch (id) {
        case EVP_PKEY_RSA:
            pcName = "RSA";
            break;
        case EVP_PKEY_SM2:
            pcName = "SM2";
            break;
        case EVP_PKEY_EC:
            pcName = "EC";
            if (EVP_PKEY_is_sm2(pkey_)) {
                pcName = "SM2";
            }
            break;
        case EVP_PKEY_ED25519:
            pcName = "ED25519";
            break;
        default:
            pcName = nullptr;
            break;
    }
#endif
    if (pcName == nullptr) {
        return "NONE";
    }
    return pcName;
}

bool EccKeyPair::GenerateKeyPair(int bits, const std::string &sParams) {
    bool rv = false;
    int id  = EVP_PKEY_EC;
    int nid = NID_X9_62_prime256v1;
    unsigned char *pucAppData = nullptr;
    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_CTX *ctx = nullptr;
    ENGINE *engine = nullptr;
    if (StringUtils::ContainIgnoreCaseWith(sParams, "ECC")) {
        id  = EVP_PKEY_EC;
        nid = NID_X9_62_prime256v1;
    } else if (StringUtils::ContainIgnoreCaseWith(sParams, "SM2")) {
        id  = EVP_PKEY_EC;
        nid = NID_sm2;
    } else if (StringUtils::ContainIgnoreCaseWith(sParams, "BRAINPOOL_P256R1")) {
        id  = EVP_PKEY_EC;
        nid = NID_brainpoolP256r1;
    }
    engine = ENGINE_by_id(engine_id);
    if (!(ctx = EVP_PKEY_CTX_new_id(id, engine))) {
        LOGM_OPENSSL_ERRORS();
        goto cleanup;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        LOGM_OPENSSL_ERRORS();
        goto cleanup;
    }
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
    pucAppData = (unsigned char *)OPENSSL_malloc(4);
    if (pucAppData != nullptr) {
        IntUtils::IntToBytes(nid, pucAppData);
    }
    EVP_PKEY_CTX_set_app_data(ctx, pucAppData);
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        LOGM_OPENSSL_ERRORS();
        goto cleanup;
    }
    pkey_ = pkey;
    rv = true;
cleanup:
    if (engine) {
        ENGINE_free(engine);
    }
    OPENSSL_free(pucAppData);
    EVP_PKEY_CTX_free(ctx);
    return rv;
}

bool EccKeyPair::ImportRawPrivateKey(const std::string &sParams,
                                     std::vector<unsigned char> &vRawKey) {
    int ret = false;
    int nid = NID_X9_62_prime256v1;
    EVP_PKEY *pkey = nullptr;
    BIGNUM *bprv = nullptr;
    EC_KEY   *key   = nullptr;
    EC_GROUP *group = nullptr;
    EC_POINT *point = nullptr;
    if (vRawKey.empty()) {
        goto cleanup;
    }
    if (StringUtils::ContainIgnoreCaseWith(sParams, "ECC")) {
        nid = NID_X9_62_prime256v1;
    } else if (StringUtils::ContainIgnoreCaseWith(sParams, "SM2")) {
        nid = NID_sm2;
    } else if (StringUtils::ContainIgnoreCaseWith(sParams, "ED25519")) {
        nid = NID_ED25519;
    } else {
        goto cleanup;
    }
    bprv = BN_bin2bn(vRawKey.data(), (int)vRawKey.size(), nullptr);
    if (!(group = EC_GROUP_new_by_curve_name(nid)) ||
        !(point = EC_POINT_new(group))) {
        goto cleanup;
    }
    key = EC_KEY_new_by_curve_name(nid);
    pkey = EVP_PKEY_new();
    if (!(EC_POINT_mul(group, point, bprv, nullptr, nullptr, nullptr)) ||
        !(EC_KEY_set_public_key(key, point)) ||
        !(EC_KEY_set_private_key(key, bprv))) {
        goto cleanup;
    }
    EVP_PKEY_assign_EC_KEY(pkey, key);
    pkey_ = pkey;
    ret = true;
cleanup:
    BN_free(bprv);
    EC_GROUP_free(group);
    EC_POINT_free(point);
    return ret;
}

bool EccKeyPair::ImportDerPublicKey(const std::vector<unsigned char>& vDerKey) {
    auto *pucInput = (unsigned char *)vDerKey.data();
    auto len = (long)vDerKey.size();
    const unsigned char *pp = pucInput;
    if (d2i_PUBKEY(&pkey_, &pp, len)) {
        return true;
    }
    return false;
}

bool EccKeyPair::ImportDerPrivateKey(const std::vector<unsigned char>& vDerKey) {
    auto *pucInput = (unsigned char *)vDerKey.data();
    auto len = (long)vDerKey.size();
    const unsigned char *pp = pucInput;
    if (pkey_) {
        EVP_PKEY_free(pkey_);
        pkey_ = nullptr;
    }
    if (d2i_AutoPrivateKey(&pkey_, &pp, len)) {
        return true;
    }
    return false;
}

bool EccKeyPair::ExportDerPublicKey(std::vector<unsigned char>& vDerKey) {
    unsigned char *buffer = nullptr;
    int buffer_len;
    if (pkey_ == nullptr) {
        return false;
    }
    buffer_len = i2d_PUBKEY(pkey_, &buffer);
    if (buffer_len <= 0) {
        OPENSSL_free(buffer);
        return false;
    }
    vDerKey.clear();
    vDerKey.assign(buffer, buffer + buffer_len);
    OPENSSL_free(buffer);
    return true;
}

bool EccKeyPair::ExportDerPrivateKey(std::vector<unsigned char>& vDerKey) {
    unsigned char *buffer = nullptr;
    int buffer_len;
    if (pkey_ == nullptr) {
        return false;
    }
    buffer_len = i2d_PrivateKey(pkey_, &buffer);
    if (buffer_len <= 0) {
        OPENSSL_free(buffer);
        return false;
    }
    vDerKey.clear();
    vDerKey.assign(buffer, buffer + buffer_len);
    OPENSSL_free(buffer);
    return true;
}

EVP_PKEY *EccKeyPair::GetPrivateKey() {
    return pkey_;
}

EVP_PKEY *EccKeyPair::GetPublicKey() {
    return pkey_;
}


