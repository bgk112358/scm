// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "rsa_encipher.h"
#include <openssl/engine.h>
#include "util/error_utils.h"

using namespace cyber;

static constexpr auto engine_id = "cyber_security";

bool RsaEncipher::EncryptData(IKeyPair* keyPair,
                              const std::vector<uint8_t> &plainData,
                              std::vector<uint8_t> &cipherData) {
    bool result = false;
    EVP_PKEY_CTX *ctx = nullptr;
    EVP_PKEY *pkey;
    unsigned char *pucBuffer = nullptr;
    size_t iBufferLen = 1024;
    Openssl_error_clear();
    if (keyPair == nullptr || keyPair->GetPrivateKey() == nullptr)
    {
        Cyber_error(error::Code::IndataErr);
        goto cleanup;
    }
    pkey = keyPair->GetPrivateKey();
    if (!(ctx = EVP_PKEY_CTX_new(pkey, nullptr)))
    {
        Openssl_error("RsaEncipher ctx new fail.");
        goto cleanup;
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0)
    {
        Openssl_error("RsaEncipher encrypt init fail.");
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
        Openssl_error("RsaEncipher encrypt fail.");
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

bool RsaEncipher::DecryptData(IKeyPair* keyPair,
                              const std::vector<uint8_t> &cipherData,
                              std::vector<uint8_t> &plainData) {
    bool result = false;
    EVP_PKEY_CTX *ctx = nullptr;
    unsigned char *buffer = nullptr;
    size_t buffer_size = 1024;
    EVP_PKEY *pkey;
    ENGINE *pEngine = ENGINE_by_id(engine_id);
    if (keyPair == nullptr || keyPair->GetPrivateKey() == nullptr)
    {
        Cyber_error(error::Code::IndataErr);
        goto cleanup;
    }
    pkey = keyPair->GetPrivateKey();
    if (!(ctx = EVP_PKEY_CTX_new(pkey, pEngine)))
    {
        Openssl_error("RsaEncipher ctx new fail.");
        goto cleanup;
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0)
    {
        Openssl_error("RsaEncipher decrypt init fail.");
        goto cleanup;
    }
    buffer_size += cipherData.size();
    buffer = (unsigned char *)OPENSSL_malloc(buffer_size);
    if (buffer == nullptr)
    {
        Openssl_error("OPENSSL_malloc fail.");
        goto cleanup;
    }
    if (EVP_PKEY_decrypt(ctx, buffer, &buffer_size,
                         cipherData.data(), cipherData.size()) != 1)
    {
        Openssl_error("RsaEncipher decrypt fail.");
        goto cleanup;
    }
    plainData.clear();
    plainData.assign(buffer, buffer + buffer_size);
    result = true;
cleanup:
    if (pEngine)
    {
        ENGINE_free(pEngine);
    }
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(buffer);
    return result;
}
