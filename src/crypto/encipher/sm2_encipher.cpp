// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "sm2_encipher.h"
#include <openssl/engine.h>
#include "util/error_utils.h"

using namespace cyber;

static constexpr auto engine_id = "cyber_security";

bool Sm2Encipher::EncryptData(IKeyPair *keyPair,
                              const std::vector<uint8_t> &plainData,
                              std::vector<uint8_t> &cipherData) {
    bool result = false;
    EVP_PKEY_CTX *ctx = nullptr;
    EVP_PKEY *pkey;
    unsigned char *pucBuffer = nullptr;
    size_t iBufferLen = 128;
    Openssl_error_clear();
    if (keyPair == nullptr || keyPair->GetPublicKey() == nullptr)
    {
        Cyber_error(error::Code::IndataErr);
        goto cleanup;
    }
    pkey = keyPair->GetPublicKey();
    if (!(ctx = EVP_PKEY_CTX_new(pkey, nullptr)))
    {
        Openssl_error("Sm2Encipher ctx new fail.");
        goto cleanup;
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0)
    {
        Openssl_error("Sm2Encipher encrypt init fail.");
        goto cleanup;
    }
    iBufferLen += plainData.size();
    pucBuffer = (unsigned char *)OPENSSL_malloc(iBufferLen);
    if (pucBuffer == nullptr)
    {
        Openssl_error("OPENSSL_malloc fail.");
        goto cleanup;
    }
    if (EVP_PKEY_encrypt(ctx, pucBuffer, &iBufferLen,
                         plainData.data(), plainData.size()) != 1)
    {
        Openssl_error("Sm2Encipher encrypt fail.");
        goto cleanup;
    }
    cipherData.clear();
    cipherData.assign(pucBuffer, pucBuffer + iBufferLen);
    result = true;
cleanup:
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(pucBuffer);
    return result;
}

bool Sm2Encipher::DecryptData(IKeyPair *keyPair,
                              const std::vector<uint8_t> &cipherData,
                              std::vector<uint8_t> &plainData) {
    bool result = false;
    EVP_PKEY_CTX *ctx = nullptr;
    unsigned char *pucBuffer = nullptr;
    size_t iBufferLen = 1024;
    EVP_PKEY *pkey;
    ENGINE *pEngine = ENGINE_by_id(engine_id);
    Openssl_error_clear();
    if (keyPair == nullptr || keyPair->GetPrivateKey() == nullptr)
    {
        Cyber_error(error::Code::IndataErr);
        goto cleanup;
    }
    pkey = keyPair->GetPrivateKey();

    if (EVP_PKEY_is_sm2(pkey)) {
        EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
    }

    if (!(ctx = EVP_PKEY_CTX_new(pkey, pEngine)))
    {
        Openssl_error("Sm2Encipher ctx new fail.");
        goto cleanup;
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0)
    {
        Openssl_error("Sm2Encipher decrypt init fail.");
        goto cleanup;
    }
    iBufferLen += cipherData.size();
    pucBuffer = (unsigned char *)OPENSSL_malloc(iBufferLen);
    if (pucBuffer == nullptr)
    {
        Openssl_error("OPENSSL_malloc fail.");
        goto cleanup;
    }
    if (EVP_PKEY_decrypt(ctx, pucBuffer, &iBufferLen,
                         cipherData.data(), cipherData.size()) != 1)
    {
        Openssl_error("Sm2Encipher decrypt fail.");
        goto cleanup;
    }
    plainData.clear();
    plainData.assign(pucBuffer, pucBuffer + iBufferLen);
    result = true;
cleanup:
    if (pEngine) {
        ENGINE_free(pEngine);
    }
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(pucBuffer);
    return result;
}
