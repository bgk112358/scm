// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "cyber_ecc.h"
#include "iengine.h"
#include "engine_factory.h"
#include "engine_utils.h"
#include "engine_config.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include "int_utils.h"

using namespace cyber;

// Generate keypair
int engine_ecc_method_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
#if ENGINE_DEBUG
    fprintf(stdout, "%s\n", __func__);
#endif
    int curve = NID_X9_62_prime256v1, rv = -1;
    ECCPUBLICKEY pstEccPublicKey = {0};
    std::unique_ptr<IEngine> pFactory = nullptr;
    EC_KEY *pKey = nullptr;
    BIGNUM *bx = nullptr, *by = nullptr;
    unsigned char *pucVal = nullptr;
    if (ctx == nullptr || pkey == nullptr) {
        ENGINE_LOG(ERROR, "Parameter fail.");
        goto cleanup;
    }
    pucVal = (unsigned char *)EVP_PKEY_CTX_get_app_data(ctx);
    if (pucVal) {
        curve = IntUtils::BytesToInt(pucVal);
    }
    pFactory = EngineFactory::Create();
    if (pFactory == nullptr) {
        ENGINE_LOG(ERROR, "Create engine fail.");
        goto cleanup;
    }

    rv = pFactory->GenerateEccKeyPair(nullptr, curve, &pstEccPublicKey);
    if ( rv != 0) {
        ENGINE_LOG(ERROR, "GenerateEccKeyPair fail, fail code: " << rv);
        goto cleanup;
    }
    pKey = EC_KEY_new_by_curve_name(curve);
    if (pKey == nullptr) {
        ENGINE_LOG(ERROR, "EC_KEY_new_by_curve_name fail.");
        goto cleanup;
    }
    bx = BN_bin2bn(pstEccPublicKey.x, (int)pstEccPublicKey.bits / 8, nullptr);
    by = BN_bin2bn(pstEccPublicKey.y, (int)pstEccPublicKey.bits / 8, nullptr);
    if (bx == nullptr || by == nullptr) {
        ENGINE_LOG(ERROR, "BN_bin2bn fail.");
        goto cleanup;
    }
    if (EC_KEY_set_public_key_affine_coordinates(pKey, bx, by) != 1) {
        ENGINE_LOG(ERROR, "EC_KEY_set_public_key_affine_coordinates fail.");
        goto cleanup;
    }
    rv = EVP_PKEY_set1_EC_KEY(pkey, pKey);
cleanup:
    BN_free(bx);
    BN_free(by);
    EC_KEY_free(pKey);
    return rv;
}

// Make signature
// calling soft method
int engine_ecc_method_default_sign(EVP_PKEY_CTX *ctx,
                                   uint8_t *sig, size_t *siglen,
                                   const uint8_t *tbs, size_t tbslen)
{
#if ENGINE_DEBUG
    fprintf(stdout, "%s\n", __func__);
#endif
    EVP_PKEY *pkey;
    const EVP_PKEY_METHOD *method;
    // default rsa method.
    int (*sign_init) (EVP_PKEY_CTX *ctx);
    int (*sign) (EVP_PKEY_CTX *, unsigned char *, size_t *, const unsigned char *, size_t);
    if (ctx == nullptr) {
        ENGINE_LOG(ERROR, "ctx is nullptr.");
        return -1;
    }
    if ((pkey = EVP_PKEY_CTX_get0_pkey(ctx))) {
        *siglen = EVP_PKEY_size(pkey);
    }
    if (sig == nullptr) {
        return 1;
    }
    method = EVP_PKEY_meth_find(EVP_PKEY_base_id(pkey));
    if (method == nullptr) {
        ENGINE_LOG(ERROR, "method is nullptr.");
        return -1;
    }
    EVP_PKEY_meth_get_sign(method, &sign_init, &sign);
    if (sign == nullptr) {
        ENGINE_LOG(ERROR, "sign is nullptr.");
        return -1;
    }
    return sign(ctx, sig, siglen, tbs, tbslen);
}

// calling hardware method here tbs len is 32 bytes
int engine_ecc_method_sign(EVP_PKEY_CTX *ctx,
                           uint8_t *sig, size_t *siglen,
                           const uint8_t *tbs, size_t tbslen)
{
#if ENGINE_DEBUG
    fprintf(stdout, "%s\n", __func__);
#endif
    printf("******** Method sign ******** %s\n", __func__);
    int rv = -1;
    unsigned char pucDataOut[256] = {0};
    unsigned int puiDataOutLen = 256;
    std::unique_ptr<IEngine> pFactory;
    if (ctx == nullptr || tbs == nullptr) {
        ENGINE_LOG(ERROR, "Parameter fail.");
        goto cleanup;
    }
    pFactory = EngineFactory::Create();
    if (pFactory == nullptr) {
        ENGINE_LOG(ERROR, "Create engine fail.");
        goto cleanup;
    }
    if (pFactory->EccSign(
            nullptr, (unsigned char *)tbs, tbslen, pucDataOut, &puiDataOutLen) != 0) {
        ENGINE_LOG(ERROR, "EccSign fail");
        goto cleanup;
    }
    if (sig)    memcpy(sig, pucDataOut, puiDataOutLen);
    if (siglen) *siglen = puiDataOutLen;
    rv = 1;
cleanup:
    return rv;
}

int engine_ecc_method_default_digestsign(EVP_MD_CTX *ctx,
                                         unsigned char *sig, size_t *siglen,
                                         const unsigned char *tbs, size_t tbslen)
{
#if ENGINE_DEBUG
    fprintf(stdout, "%s\n", __func__);
#endif
    unsigned int mdSize = 64;
    unsigned char md[64] = {0};
    EVP_PKEY_CTX *pkeyctx;
    const EVP_MD *sigmd;
    if (ctx == nullptr || tbs == nullptr) {
        ENGINE_LOG(ERROR, "Parameter fail.");
        return -1;
    }
    if (!(pkeyctx = EVP_MD_CTX_pkey_ctx(ctx)))
    {
        ENGINE_LOG(ERROR, "EVP_MD_CTX_pkey_ctx fail.");
        return -1;
    }
    sigmd = EVP_MD_CTX_md(ctx);
    if (sigmd == nullptr) {
        EVP_PKEY_CTX_get_signature_md(pkeyctx, &sigmd);
    }
    if (sigmd == nullptr) {
        sigmd = EVP_sha512();
    }
    if (EVP_Digest(tbs, tbslen, md, &mdSize, sigmd, nullptr) != 1) {
        fprintf(stderr, "[%s] EVP_Digest error. \n", __func__);
    }
    return engine_ecc_method_default_sign(pkeyctx, sig, siglen, md, mdSize);
}

int engine_ecc_method_digestsign(EVP_MD_CTX *ctx,
                                 unsigned char *sig, size_t *siglen,
                                 const unsigned char *tbs, size_t tbslen)
{
#if ENGINE_DEBUG
    fprintf(stdout, "%s\n", __func__);
#endif
    unsigned int mdSize = 64;
    unsigned char md[64] = { 0 };
    EVP_PKEY_CTX *pkeyctx;
    const EVP_MD *sigmd;
    if (ctx == nullptr || tbs == nullptr) {
        fprintf(stderr, "[%s] input error. \n", __func__);
        return -1;
    }
    if (!(pkeyctx = EVP_MD_CTX_pkey_ctx(ctx))) {
        fprintf(stderr, "[%s] EVP_MD_CTX_pkey_ctx error. \n", __func__);
        return -1;
    }
    sigmd = EVP_MD_CTX_md(ctx);
    if (sigmd == nullptr) {
        EVP_PKEY_CTX_get_signature_md(pkeyctx, &sigmd);
    }
    if (sigmd == nullptr) {
        sigmd = EVP_sha512();
    }
    if (EVP_Digest(tbs, tbslen, md, &mdSize, sigmd, nullptr) != 1) {
        fprintf(stderr, "[%s] EVP_Digest error. \n", __func__);
    }
    return engine_ecc_method_sign(pkeyctx, sig, siglen, md, mdSize);
}


int engine_ecc_method_verify(EVP_PKEY_CTX *ctx,
                             const unsigned char *sig, size_t siglen,
                             const unsigned char *tbs, size_t tbslen)
{
#if ENGINE_DEBUG
    fprintf(stdout, "%s\n", __func__);
#endif
    int rv = -1;
    EVP_PKEY *evp_pkey;
    const EC_KEY  *ec_key;
    if (ctx == nullptr || sig == nullptr || tbs == nullptr) {
        ENGINE_LOG(ERROR, "Parameter fail.");
        goto cleanup;
    }
    evp_pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    if (evp_pkey == nullptr) {
        ENGINE_LOG(ERROR, "EVP_PKEY_CTX_get0_pkey fail.");
        goto cleanup;
    }
    ec_key = EVP_PKEY_get0_EC_KEY(evp_pkey);
    if (ec_key == nullptr) {
        ENGINE_LOG(ERROR, "EVP_PKEY_get0_EC_KEY fail.");
        goto cleanup;
    }
    rv = ECDSA_verify(0, tbs, (int)tbslen, sig, (int)siglen, (EC_KEY *)ec_key);
    if (rv != 1) {
        ENGINE_LOG(ERROR, "ECDSA_verify fail.");
    }
cleanup:
    return rv;
}

int engine_ecc_method_digestverify(EVP_MD_CTX *ctx,
                                   const unsigned char *sig, size_t siglen,
                                   const unsigned char *tbs, size_t tbslen)
{
#if ENGINE_DEBUG
    fprintf(stdout, "%s\n", __func__);
#endif
    unsigned int mdSize = 64;
    unsigned char md[64] = {0};
    EVP_PKEY_CTX *pkeyctx;
    const EVP_MD *sigmd;
    if (ctx == nullptr || tbs == nullptr) {
        ENGINE_LOG(ERROR, "Parameter fail.");
        return -1;
    }
    if (!(pkeyctx = EVP_MD_CTX_pkey_ctx(ctx))) {
        ENGINE_LOG(ERROR, "EVP_MD_CTX_pkey_ctx fail.");
        return -1;
    }
    sigmd = EVP_MD_CTX_md(ctx);
    if (sigmd == nullptr) {
        EVP_PKEY_CTX_get_signature_md(pkeyctx, &sigmd);
    }
    if (sigmd == nullptr) {
        sigmd = EVP_sha512();
    }
    if (EVP_Digest(tbs, tbslen, md, &mdSize, sigmd, nullptr) != 1) {
        ENGINE_LOG(ERROR, "EVP_Digest fail.");
    }
    return engine_ecc_method_verify(pkeyctx, sig, siglen, md, mdSize);
}