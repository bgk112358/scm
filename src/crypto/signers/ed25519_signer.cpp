// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "ed25519_signer.h"
#include <openssl/evp.h>
#include <openssl/engine.h>
#include "common/config.h"
#include "util/error_utils.h"

using namespace cyber;

static constexpr auto engine_id = "cyber_security";

std::string Ed25519Signer::GetAlgorithm() {
    return "ED25519";
}

bool Ed25519Signer::MakeSignature(IKeyPair* keyPair,
                                  const std::string& sHashAlgorithm,
                                  const std::vector<uint8_t>& vMessage,
                                  std::vector<uint8_t>& vSignature) {
    bool result = false;
    unsigned char ucSignature[128] = {0};
    size_t  uiSignatureLen   = 128;
    EVP_PKEY *pkey;
    EVP_MD_CTX *mctx = nullptr;
    EVP_PKEY_CTX *pctx = nullptr;
    ENGINE *engine = ENGINE_by_id(engine_id);
    if (keyPair == nullptr) {
        Cyber_error(error::IndataErr);
        goto cleanup;
    }
    if (!(pkey = keyPair->GetPrivateKey())) {
        Cyber_error(error::IndataErr);
        goto cleanup;
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if(EVP_PKEY_get_base_id(pkey) != EVP_PKEY_ED25519)
#else
    if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) 
#endif
    {
        Cyber_error_message("The pkey is not ed25519.");
        goto cleanup;
    }
    Openssl_error_clear();
    if (!(mctx = EVP_MD_CTX_new())) {
        Openssl_error("Ed25519 md ctx new fail.");
        goto cleanup;
    }
    if (!(pctx = EVP_PKEY_CTX_new(pkey, nullptr))) {
        Openssl_error("Ed25519 pkey ctx new fail.");
        goto cleanup;
    }
    EVP_MD_CTX_set_pkey_ctx(mctx, pctx);
    if (EVP_DigestSignInit(mctx, nullptr, nullptr, engine, pkey) != 1) {
        Openssl_error("Ed25519 sign init fail.");
        goto cleanup;
    }
    if (EVP_DigestSign(mctx, ucSignature, &uiSignatureLen,
                       vMessage.data(), vMessage.size()) != 1) {
        Openssl_error("Ed25519 sign fail.");
        goto cleanup;
    }
    vSignature.clear();
    vSignature.assign(ucSignature, ucSignature + uiSignatureLen);
    result = true;
cleanup:
    if (engine) {
        ENGINE_free(engine);
    }
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_CTX_free(pctx);
    return result;
}

bool Ed25519Signer::VerifySignature(IKeyPair* keyPair,
                                    const std::string& sHashAlgorithm,
                                    const std::vector<uint8_t>& vMessage,
                                    const std::vector<uint8_t>& vSignature) {
    bool res = false;
    EVP_PKEY *pkey;
    EVP_MD_CTX *mctx = nullptr;
    EVP_PKEY_CTX *pctx = nullptr;
    if (keyPair == nullptr) {
        Cyber_error(error::IndataErr);
        goto cleanup;
    }
    if (!(pkey = keyPair->GetPublicKey())) {
        Cyber_error(error::IndataErr);
        goto cleanup;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if(EVP_PKEY_get_base_id(pkey) != EVP_PKEY_ED25519)
#else
    if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) 
#endif
    {
        Cyber_error_message("The pkey is not ed25519.");
        goto cleanup;
    }
    Openssl_error_clear();
    if (!(mctx = EVP_MD_CTX_new())) {
        Openssl_error("Ed25519 md ctx new fail.");
        goto cleanup;
    }
    if (!(pctx = EVP_PKEY_CTX_new(pkey, nullptr))) {
        Openssl_error("Ed25519 pkey ctx new fail.");
        goto cleanup;
    }
    EVP_MD_CTX_set_pkey_ctx(mctx, pctx);
    if (EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, pkey) != 1) {
        Openssl_error("Ed25519 verify init fail.");
        goto cleanup;
    }
    if (EVP_DigestVerify(mctx, vSignature.data(), vSignature.size(),
                         vMessage.data(), vMessage.size()) != 1) {
        Openssl_error("Ed25519 verify fail.");
        goto cleanup;
    }
    res = true;
cleanup:
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_CTX_free(pctx);
    return res;
}

