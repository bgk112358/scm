// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#include "catarc_engine.h"
#include "../engine_utils.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include "../external/cyber_saf.h"
#include "../handle/handler.h"

using namespace cyber;

// Internal Handle
static void *phHandle_ = nullptr;

static int isOpen_ = 0;

int CatarcEngine::Initialize()
{
    ENGINE_LOG(INFO, "Initialize");
    return 0;
}

int CatarcEngine::Finalize()
{
    ENGINE_LOG(INFO, "Finalize");
    return 0;
}

int CatarcEngine::Login(unsigned int uiUsrType,
                        unsigned char *pucContainerName,
                        unsigned int uiContainerNameLen,
                        unsigned char *pucPin,
                        unsigned int uiPinLen,
                        unsigned int *puiRemainCount)
{
    ENGINE_LOG(INFO, "[CYBER]: Login.");
    return 0;
}

int CatarcEngine::Logout(unsigned int uiUsrType) {
    ENGINE_LOG(INFO, "[CYBER]: Logout.");
    return 0;
}

int CatarcEngine::GenerateRsaKeyPair(unsigned char *pucKeyID,
                                     unsigned int uiKeyBits,
                                     PRSAPUBLICKEY pstRSAPublicKey) {
    ENGINE_LOG(INFO, "[CYBER]: GenerateRsaKeyPair.");
    return 0;
}

int CatarcEngine::GetRsaPublicKey(unsigned char *pucKeyID,
                                  PRSAPUBLICKEY pstRSAPublicKey) {
    ENGINE_LOG(INFO, "[CYBER]: GetRsaPublicKey.");
    return 0;
}

int CatarcEngine::RsaPublicKeyCalc(RSAPUBLICKEY stRSAPublicKey,
                                   unsigned char *pucDataIn,
                                   unsigned int uiDataInLen,
                                   unsigned char *pucDataOut,
                                   unsigned int *puiDataOutLen) {
    ENGINE_LOG(INFO, "[CYBER]: RsaPublicKeyCalc.");
    return 0;
}

int CatarcEngine::RsaPrivateKeyCalc(unsigned char *pucKeyID,
                                    unsigned char *pucDataIn,
                                    unsigned int uiDataInLen,
                                    unsigned char *pucDataOut,
                                    unsigned int *puiDataOutLen) {
    ENGINE_LOG(INFO, "[CYBER]: RsaPrivateKeyCalc.");
    return 0;
}

int CatarcEngine::GenerateEccKeyPair(unsigned char *pucKeyID,
                                     unsigned int uiCurveType,
                                     PECCPUBLICKEY pstEccPublicKey) {
    ENGINE_LOG(INFO, "[CYBER]: GenerateEccKeyPair.");
    if (pstEccPublicKey == nullptr) {
        return -1;
    }
    EC_KEY *ec_key = EC_KEY_new_by_curve_name((int)uiCurveType);
    if (ec_key == nullptr) {
        return -1;
    }
    if (EC_KEY_generate_key(ec_key) != 1) {
        EC_KEY_free(ec_key);
        return -1;
    }
    const EC_POINT *pub_key = EC_KEY_get0_public_key(ec_key);
    if (pub_key == nullptr) {
        EC_KEY_free(ec_key);
        return -1;
    }
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    if (EC_POINT_get_affine_coordinates(group, pub_key, x, y, nullptr) != 1) {
        BN_free(x);
        BN_free(y);
        EC_KEY_free(ec_key);
        return -1;
    }
    pstEccPublicKey->bits = 256;
    BN_bn2bin(x, pstEccPublicKey->x);
    BN_bn2bin(y, pstEccPublicKey->y);

    BN_free(x);
    BN_free(y);
    EC_KEY_free(ec_key);
    return 0;
}

int CatarcEngine::GetEccPublicKey(unsigned char *pucKeyID,
                                  PECCPUBLICKEY pstEccPublicKey) {

    ENGINE_LOG(INFO, "[CYBER]: GetEccPublicKey ecc.");
    return 0;
}

int CatarcEngine::EccSign(unsigned char *pucKeyID,
                          unsigned char *pucDgstIn,
                          unsigned int uiDgstInLen,
                          unsigned char *pucDataOut,
                          unsigned int *puiDataOutLen) {
    ENGINE_LOG(INFO, "[CYBER]: EccSign");
    Handler *handler = Handler::Instance();
    const char *GMID = "1234567812345678";
    int GMIDLen = 16;
    unsigned char pucPrivateKey[2048] = {0};
    unsigned int uiPrivateKeyLen = 2048;
    unsigned char ucSignature[1024] = {0};
    size_t uiSignatureLen = 1024;
    const unsigned char *p = nullptr;
    EVP_MD_CTX *mctx;
    EVP_PKEY_CTX *pctx;
    EVP_PKEY *pkey = nullptr;
    if (handler == nullptr) {
        ENGINE_LOG(ERROR, "[CYBER]: Parameter error");
        return -1;
    }
    int rv = CY_SAF_InternalExportPrivateKey(
            handler,
            (unsigned char *)handler->GetContainerName().c_str(),
            (unsigned int)handler->GetContainerName().length(),
            SGD_KEYUSAGE_SIGN,
            nullptr,
            pucPrivateKey,
            &uiPrivateKeyLen);
    if (rv != 0) {
        ENGINE_LOG(ERROR, "[CYBER]: Get PrivateKey error");
        goto cleanup;
    }
    p = pucPrivateKey;
    if (!(mctx = EVP_MD_CTX_new())) {
        ENGINE_LOG(ERROR, "[CYBER]: Memory error");
        rv = -1;
        goto cleanup;
    }
    pkey = d2i_AutoPrivateKey(nullptr, &p, uiPrivateKeyLen);
    if (pkey == nullptr) {
        ENGINE_LOG(ERROR, "[CYBER]: d2i_AutoPrivateKey error");
        rv = -1;
        goto cleanup;
    }
    EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
    if (!(pctx = EVP_PKEY_CTX_new(pkey, nullptr))) {
        ENGINE_LOG(ERROR, "[CYBER]: Memory error");
        rv = -1;
        goto cleanup;
    }
    EVP_PKEY_CTX_set1_id(pctx, GMID, GMIDLen);
    EVP_MD_CTX_set_pkey_ctx(mctx, pctx);
    if (EVP_DigestSignInit(mctx, nullptr, EVP_sm3(), nullptr, pkey) != 1) {
        ENGINE_LOG(ERROR, "[CYBER]: DigestSignInit");
        rv = -1;
        goto cleanup;
    }
    if (EVP_DigestSign(mctx, ucSignature, &uiSignatureLen,
                         pucDgstIn, uiDgstInLen) != 1) {
        ENGINE_LOG(ERROR, "[CYBER]: DigestSign");
        rv = -1;
        goto cleanup;
    }
    *puiDataOutLen = uiSignatureLen;
    memcpy(pucDataOut, ucSignature, uiSignatureLen);
    rv = 0;
cleanup:
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_CTX_free(pctx);
    return rv;
}

int CatarcEngine::EccVerifySign(ECCPUBLICKEY stEccPublicKey,
                                unsigned char *pucDgstIn,
                                unsigned int uiDgstInLen,
                                unsigned char *pucSignData,
                                unsigned int puiSignDataLen) {
    return -1;
}

int CatarcEngine::EccDecrypt(unsigned char *pucKeyID,
                             unsigned char *pucDataIn,
                             unsigned int uiDataInLen,
                             unsigned char *pucDataOut,
                             unsigned int *puiDataOutLen) {
    ENGINE_LOG(INFO, "[CYBER]: EccDecrypt");
    Handler *handler = Handler::Instance();
    EVP_PKEY *pkey = nullptr;
    const unsigned char *pp = nullptr;
    EVP_PKEY_CTX *pctx = nullptr;
    EVP_MD_CTX *mctx = nullptr;
    unsigned char ucOutBuffer[1024] = {0};
    size_t uiOutBufferLen = 1024;
    unsigned char pucPrivateKey[2048] = {0};
    unsigned int uiPrivateKeyLen = 1024;
    if (handler == nullptr) {
        return -1;
    }
    int rv = CY_SAF_InternalExportPrivateKey(
            handler,
            (unsigned char *)handler->GetContainerName().c_str(),
            (unsigned int)handler->GetContainerName().length(),
            SGD_KEYUSAGE_SIGN,
            nullptr,
            pucPrivateKey,
            &uiPrivateKeyLen);
    // 需要判断是什么算法， 这里以 SM2 算法举例
    if (rv != 0) {
        ENGINE_LOG(ERROR, "[CYBER]: Get PrivateKey error");
        goto cleanup;
    }
    pp = pucPrivateKey;
    d2i_AutoPrivateKey(&pkey, &pp, uiPrivateKeyLen);

    if (!(mctx = EVP_MD_CTX_new())) {
        rv = -1;
        goto cleanup;
    }
    if (EVP_PKEY_is_sm2(pkey)) {
        EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
    }
    if (!(pctx = EVP_PKEY_CTX_new(pkey, nullptr))) {
        rv = -1;
        goto cleanup;
    }
    EVP_MD_CTX_set_pkey_ctx(mctx, pctx);
    if (EVP_PKEY_decrypt_init(pctx) <= 0) {
        rv = -1;
        goto cleanup;
    }
    if (EVP_PKEY_decrypt(pctx, ucOutBuffer, &uiOutBufferLen,
                         pucDataIn, uiDataInLen) != 1) {
        rv = -1;
        goto cleanup;
    }
    *puiDataOutLen = uiOutBufferLen;
    memcpy(pucDataOut, ucOutBuffer, uiOutBufferLen);
    rv = 0;
cleanup:
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_CTX_free(pctx);
    return rv;
}
