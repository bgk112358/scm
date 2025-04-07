// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
// https://docs.openssl.org/1.1.1/man7/SM2/#notes

#include "sm2_signer.h"
#include <openssl/evp.h>
#include <openssl/engine.h>
#include "util/error_utils.h"

static constexpr auto engine_id = "cyber_security";
static const char *GMID = "1234567812345678";
static int GMIDLen = 16;

using namespace cyber;

std::string Sm2Signer::GetAlgorithm() {
    return "SM2";
}

bool Sm2Signer::MakeSignature(IKeyPair *keyPair,
                              const std::string &hashAlgorithm,
                              const std::vector<uint8_t> &vMessage,
                              std::vector<uint8_t> &vSignature) {
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
    Openssl_error_clear();
    if (!(mctx = EVP_MD_CTX_new())) {
        Openssl_error("SM2 md ctx new fail.");
        goto cleanup;
    }
    if (EVP_PKEY_is_sm2(pkey)) {
        EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
    }
    if (!(pctx = EVP_PKEY_CTX_new(pkey, engine))) {
        Openssl_error("SM2 pkey ctx new fail.");
        goto cleanup;
    }
    EVP_PKEY_CTX_set1_id(pctx, GMID, GMIDLen);
    EVP_MD_CTX_set_pkey_ctx(mctx, pctx);
    if (EVP_DigestSignInit(mctx, nullptr, EVP_sm3(), nullptr, pkey) != 1) {
        Openssl_error("SM2 sign init fail.");
        goto cleanup;
    }
    if (EVP_DigestSign(mctx, ucSignature, &uiSignatureLen,
                       vMessage.data(), vMessage.size()) != 1) {
        Openssl_error("SM2 sign fail.");
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

bool Sm2Signer::VerifySignature(IKeyPair *keyPair,
                                const std::string &hashAlgorithm,
                                const std::vector<uint8_t> &vMessage,
                                const std::vector<uint8_t> &vSignature) {
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
    Openssl_error_clear();
    if (!(mctx = EVP_MD_CTX_new())) {
        Openssl_error("SM2 md ctx new fail.");
        goto cleanup;
    }
    if (!(pctx = EVP_PKEY_CTX_new(pkey, nullptr))) {
        Openssl_error("SM2 pkey ctx new fail.");
        goto cleanup;
    }
    EVP_PKEY_CTX_set1_id(pctx, GMID, GMIDLen);
    EVP_MD_CTX_set_pkey_ctx(mctx, pctx);
    if (EVP_DigestVerifyInit(mctx, nullptr, nullptr, nullptr, pkey) != 1) {
        Openssl_error("SM2 verify init fail.");
        goto cleanup;
    }
    if (EVP_DigestVerify(mctx, vSignature.data(), vSignature.size(),
                         vMessage.data(), vMessage.size()) != 1) {
        Openssl_error("SM2 verify fail.");
        goto cleanup;
    }
    res = true;
    cleanup:
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_CTX_free(pctx);
    return res;
}
