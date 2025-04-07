// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "rsa_keypair.h"
#include <openssl/engine.h>
#include "util/openssl_utils.h"

using namespace cyber;

static constexpr auto engine_id = "cyber_security";

std::string RsaKeyPair::GetAlgorithmName() {
    return "RSA";
}

bool RsaKeyPair::GenerateKeyPair(int bits, const std::string &sParams) {
    bool rv = false;
    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_CTX *ctx;
    ENGINE *engine = ENGINE_by_id(engine_id);
    Openssl_error_clear();
    if (!(ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, engine))) {
        Openssl_error("ctx new");
        goto cleanup;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        Openssl_error("keygen init");
        goto cleanup;
    }
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        Openssl_error("keygen");
        goto cleanup;
    }
    pkey_ = pkey;
    rv = true;
cleanup:
    if (engine) {
        ENGINE_free(engine);
    }
    EVP_PKEY_CTX_free(ctx);
    return rv;
}

bool RsaKeyPair::ImportRawPrivateKey(const std::string &sParams,
                                     std::vector<unsigned char> &vRawKey) {
    params_ = sParams;
    return false;
}

bool RsaKeyPair::ImportDerPublicKey(const std::vector<unsigned char>& vDerKey) {
    auto *pucInput = (unsigned char *)vDerKey.data();
    auto len = (long)vDerKey.size();
    const unsigned char *pp = pucInput;
    if (pkey_ != nullptr) {
        EVP_PKEY_free(pkey_);
        pkey_ = nullptr;
    }
    if (d2i_PUBKEY(&pkey_, &pp, len)) {
        return true;
    }
    return false;
}

bool RsaKeyPair::ImportDerPrivateKey(const std::vector<unsigned char>& vDerKey) {
    auto *pucInput = (unsigned char *)vDerKey.data();
    auto len = (long)vDerKey.size();
    const unsigned char *pp = pucInput;
    if (pkey_ != nullptr) {
        EVP_PKEY_free(pkey_);
        pkey_ = nullptr;
    }
    if (d2i_AutoPrivateKey(&pkey_, &pp, len)) {
        return true;
    }
    return false;
}

bool RsaKeyPair::ExportDerPublicKey(std::vector<unsigned char>& vDerKey) {
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

bool RsaKeyPair::ExportDerPrivateKey(std::vector<unsigned char>& vDerKey) {
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

EVP_PKEY *RsaKeyPair::GetPrivateKey() {
    return pkey_;
}

EVP_PKEY *RsaKeyPair::GetPublicKey() {
    return pkey_;
}


