// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "ecdsa_signer.h"
#include <openssl/evp.h>
#include <openssl/engine.h>
#include "util/util.h"
#include "engine/engine_config.h"
#include "common/config.h"

using namespace cyber;

static constexpr auto engine_id = "cyber_security";

std::string EcdsaSigner::GetAlgorithm() {
    return "ECC";
}

bool EcdsaSigner::MakeSignature(IKeyPair *keyPair,
                                const std::string &hashAlgorithm,
                                const std::vector<uint8_t> &vMessage,
                                std::vector<uint8_t> &vSignature) {
    bool result = false;
    unsigned char ucDigest[64] = {0};
    unsigned int  uiDigestLen  = 64;
    unsigned char ucSignature[512] = {0};
    size_t uiSignatureLen = 512;
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
    if(EVP_PKEY_get_base_id(pkey) != EVP_PKEY_EC)
#else
    if (EVP_PKEY_id(pkey) != EVP_PKEY_EC) 
#endif
    {
        Cyber_error_message("The pkey is not ecc.");
        goto cleanup;
    }
    Openssl_error_clear();
    if (!(pctx = EVP_PKEY_CTX_new(pkey, engine))) {
        Openssl_error("ECC pkey ctx new fail.");
        goto cleanup;
    }
    if (EVP_PKEY_sign_init(pctx) != 1) {
        Openssl_error("ECC sign init fail.");
        goto cleanup;
    }
    mdname = EVP_get_digestbyname(hashAlgorithm.data());
    EVP_PKEY_CTX_set_signature_md(pctx, mdname);
    // Digest Message
    EVP_Digest(vMessage.data(), vMessage.size(), ucDigest, &uiDigestLen, mdname,
               nullptr);
    if (EVP_PKEY_sign(pctx, ucSignature, &uiSignatureLen,
                      ucDigest, uiDigestLen) != 1) {
        Openssl_error("ECC sign fail.");
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

bool EcdsaSigner::VerifySignature(IKeyPair *keyPair,
                                  const std::string &hashAlgorithm,
                                  const std::vector<uint8_t>& vMessage,
                                  const std::vector<uint8_t>& vSignature) {
    ERR_clear_error();
    bool result = false;
    unsigned char ucDigest[64] = {0};
    unsigned int  uiDigestLen  = 64;
    EVP_PKEY_CTX *pctx = nullptr;
    const EVP_MD *mdname;
    EVP_PKEY *pkey;
    if (keyPair == nullptr) {
        Cyber_error(error::IndataErr);
        goto cleanup;
    }
    if (!(pkey = keyPair->GetPublicKey())) {
        Cyber_error(error::IndataErr);
        goto cleanup;
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if(EVP_PKEY_get_base_id(pkey) != EVP_PKEY_EC)
#else
    if (EVP_PKEY_id(pkey) != EVP_PKEY_EC)
#endif
    {
        Cyber_error_message("The pkey is not ecc.");
        goto cleanup;
    }
    Openssl_error_clear();
    if (!(pctx = EVP_PKEY_CTX_new(pkey, nullptr))) {
        Openssl_error("ECC pkey ctx new fail.");
        goto cleanup;
    }
    if (EVP_PKEY_verify_init(pctx) <= 0) {
        Openssl_error("ECC verify init fail.");
        goto cleanup;
    }

    mdname = EVP_get_digestbyname(hashAlgorithm.data());
    EVP_Digest(vMessage.data(), vMessage.size(), ucDigest, &uiDigestLen, mdname,
               nullptr);
    if (EVP_PKEY_verify(pctx,vSignature.data(), vSignature.size(),
            ucDigest, uiDigestLen) != 1) {
        Openssl_error("ECC verify fail.");
        goto cleanup;
    }

    result = true;
cleanup:
    EVP_PKEY_CTX_free(pctx);
    return result;
}


