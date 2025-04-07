// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "rsa_signer.h"
#include <openssl/engine.h>
#include "common/config.h"
#include <openssl/evp.h>
#include "util/error_utils.h"

using namespace cyber;

static constexpr auto engine_id = "cyber_security";

std::string RsaSigner::GetAlgorithm() {
    return "RSA";
}

bool RsaSigner::MakeSignature(IKeyPair *keyPair,
                              const std::string &sHashAlgorithm,
                              const std::vector<uint8_t> &vMessage,
                              std::vector<uint8_t> &vSignature) {
    bool result = false;
    unsigned char ucDigest[64] = {0};
    unsigned int  uiDigestLen  = 64;
    unsigned char ucSignature[512] = {0};
    size_t  uiSignatureLen   = 512;
    int padding = RSA_PKCS1_PADDING;
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *pctx = nullptr;
    const EVP_MD *mdname;
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
    if(EVP_PKEY_get_base_id(pkey) != EVP_PKEY_RSA)
#else
    if (EVP_PKEY_id(pkey) != EVP_PKEY_RSA) 
#endif
    {
        Cyber_error_message("pkey is not rsa.");
        goto cleanup;
    }
    Openssl_error_clear();
    if (!(pctx = EVP_PKEY_CTX_new(pkey, engine))) {
        Openssl_error("RSA pkey ctx new fail.");
        goto cleanup;
    }
    if (EVP_PKEY_sign_init(pctx) != 1) {
        Openssl_error("RSA sign init error.");
        goto cleanup;
    }
    if (padding_ == RsaPadding::PSS) {
        padding = RSA_PKCS1_PSS_PADDING;
    }
    EVP_PKEY_CTX_set_rsa_padding(pctx, padding);
    if (padding_ == RsaPadding::PSS) {
        // EVP_PKEY_CTX_set_rsa_pss_saltlen() sets the RSA PSS salt length to saltlen.
        // As its name implies it is only supported for PSS padding.
        // If this function is not called then the maximum salt length is used
        // when signing and auto detection when verifying.
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST);
    }
    mdname = EVP_get_digestbyname(sHashAlgorithm.data());
    EVP_PKEY_CTX_set_signature_md(pctx, mdname);
    // Digest Message
    EVP_Digest(vMessage.data(), vMessage.size(), ucDigest, &uiDigestLen, mdname,
               nullptr);
    if (EVP_PKEY_sign(pctx, ucSignature, &uiSignatureLen,
                      ucDigest, uiDigestLen) != 1) {
        Openssl_error("RSA sign error.");
        goto cleanup;
    }
    vSignature.clear();
    vSignature.assign(ucSignature, ucSignature + uiSignatureLen);
    result = true;
cleanup:
    if (engine) {
        ENGINE_free(engine);
    }
    EVP_PKEY_CTX_free(pctx);
    return result;
}

bool RsaSigner::VerifySignature(IKeyPair *keyPair,
                                const std::string &sHashAlgorithm,
                                const std::vector<uint8_t>& vMessage,
                                const std::vector<uint8_t>& vSignature) {
    bool result = false;
    int padding = RSA_PKCS1_PADDING;
    EVP_PKEY *pkey;
    EVP_MD_CTX *mctx = nullptr;
    EVP_PKEY_CTX *pctx = nullptr;
    const EVP_MD *mdname;
    if (keyPair == nullptr) {
        Cyber_error(error::IndataErr);
        goto cleanup;
    }
    if (!(pkey = keyPair->GetPublicKey())) {
        Cyber_error(error::IndataErr);
        goto cleanup;
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (EVP_PKEY_get_base_id(pkey) != EVP_PKEY_RSA)
#else
    if (EVP_PKEY_id(pkey) != EVP_PKEY_RSA) 
#endif
    {
        Cyber_error_message("The pkey is not rsa.");
        goto cleanup;
    }
    Openssl_error_clear();
    if (!(mctx = EVP_MD_CTX_new())) {
        Openssl_error("RSA md ctx new fail.");
        goto cleanup;
    }
    if (!(pctx = EVP_PKEY_CTX_new(pkey, nullptr))) {
        Openssl_error("RSA pkey ctx new fail.");
        goto cleanup;
    }
    if (padding_ == RsaPadding::PSS) {
        padding = RSA_PKCS1_PSS_PADDING;
    }
    EVP_MD_CTX_set_pkey_ctx(mctx, pctx);
    mdname = EVP_get_digestbyname(sHashAlgorithm.data());
    if (EVP_DigestVerifyInit(mctx, nullptr, mdname, nullptr, pkey) != 1) {
        Openssl_error("RSA verify init fail.");
        goto cleanup;
    }
    EVP_PKEY_CTX_set_rsa_padding(pctx, padding);
    if (padding_ == RsaPadding::PSS) {
        // EVP_PKEY_CTX_set_rsa_pss_saltlen() sets the RSA PSS salt length to saltlen.
        // As its name implies it is only supported for PSS padding.
        // If this function is not called then the maximum salt length is used
        // when signing and auto detection when verifying.
        // RSA_PSS_SALTLEN_DIGEST is the default parameter for the Java BC library
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST);
    }

    if (EVP_DigestVerify(mctx, vSignature.data(), vSignature.size(),
                         vMessage.data(), vMessage.size()) != 1) {
        Openssl_error("RSA verify fail.");
        goto cleanup;
    }
    result = true;
cleanup:
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_CTX_free(pctx);
    return result;
}

