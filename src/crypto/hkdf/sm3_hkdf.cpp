// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "sm3_hkdf.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include "util/openssl_utils.h"

using namespace cyber;

std::string Sm3Hkdf::GetAlgorithmName() {
    return "SM3-HKDF";
}

int Sm3Hkdf::GetHkdfSize() {
    return key_size_;
}

bool Sm3Hkdf::Compute(const std::vector<unsigned char> &ikm,
                      const std::vector<unsigned char> &info,
                      const std::vector<unsigned char> &salt,
                      size_t derived_key_size,
                      std::vector<unsigned char> &digest) {
    bool rv = false;
    EVP_PKEY_CTX *pctx = nullptr;
    unsigned char *buffer = nullptr;
    size_t buffer_len = 0;
    Openssl_error_clear();
    if (derived_key_size == 0) {
        goto cleanup;
    }
    buffer = (unsigned char *) OPENSSL_zalloc(derived_key_size);
    if (buffer == nullptr) {
        Openssl_error("zalloc");
        goto cleanup;
    }
    buffer_len = derived_key_size;
    if (!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr))) {
        Openssl_error("new");
        goto cleanup;
    }
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        Openssl_error("derive init");
        goto cleanup;
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sm3()) <= 0) {
        Openssl_error("hkdf md");
        goto cleanup;
    }
    if (!salt.empty()) {
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), (int)salt.size());
    }
    if (!ikm.empty()) {
        EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), (int)ikm.size());
    }
    if (!info.empty()) {
        EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), (int)info.size());
    }
    /* Derive the key */
    if (EVP_PKEY_derive(pctx, buffer, &buffer_len) != 1) {
        Openssl_error("derive");
        goto cleanup;
    }
    digest.clear();
    digest.assign(buffer, buffer + buffer_len);
    rv = true;
    key_size_ = (int)derived_key_size;
cleanup:
    OPENSSL_free(buffer);
    EVP_PKEY_CTX_free(pctx);
    return rv;
}
