//
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "cyber_rsa.h"
#include "engine_factory.h"
#include "engine_utils.h"
#include "engine_config.h"
#include <openssl/rsa.h>

using namespace cyber;

// Generate keypair
int engine_rsa_method_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
#if ENGINE_DEBUG
    fprintf(stdout, "%s\n", __func__);
#endif
    int bits = 2048, rv = -1;
    RSAPUBLICKEY pstRSAPublicKey = {0};
    std::unique_ptr<IEngine> pFactory;
    RSA *pRsa = nullptr;
    BIGNUM *pbn, *pbe;
    if (ctx == nullptr || pkey == nullptr) {
        ENGINE_LOG(ERROR, "Parameter fail.");
        goto cleanup;
    }
    pFactory = EngineFactory::Create();
    if (pFactory == nullptr) {
        ENGINE_LOG(ERROR, "Create Driver fail.");
        goto cleanup;
    }
    if (pFactory->GenerateRsaKeyPair(nullptr, bits, &pstRSAPublicKey) != 0) {
        ENGINE_LOG(ERROR, "GenerateRsaKeyPair fail, fail code: " << rv);
        goto cleanup;
    }
    if (!(pRsa = RSA_new())) {
        ENGINE_LOG(ERROR, "RSA_new fail");
        goto cleanup;
    }
    pbn = BN_bin2bn(pstRSAPublicKey.m, (int)pstRSAPublicKey.bits / 8, nullptr);
    pbe = BN_bin2bn(pstRSAPublicKey.e, 4, nullptr);
    if (pbn == nullptr || pbe == nullptr) {
        ENGINE_LOG(ERROR, "BN_bin2bn fail");
        goto cleanup;
    }
    RSA_set0_key(pRsa, pbn, pbe, nullptr);
    rv = EVP_PKEY_set1_RSA(pkey, pRsa);
cleanup:
    RSA_free(pRsa);
    return rv;
}

// Make signature
// calling soft method
int engine_rsa_method_default_sign(EVP_PKEY_CTX *ctx,
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

// calling hardware method
int engine_rsa_method_sign(EVP_PKEY_CTX *ctx,
                           uint8_t *sig, size_t *siglen,
                           const uint8_t *tbs, size_t tbslen)
{
#if ENGINE_DEBUG
    fprintf(stdout, "%s\n", __func__);
#endif
    int rv = -1;
    unsigned char tbsValue[2048] = {0};
    unsigned int tbsValueLen = 2048;
    int padding = 0, size = 256;
    unsigned char pucDataOut[1024] = {0};
    unsigned int puiDataOutLen = 1024;
    const EVP_MD *sigmd = nullptr;
    EVP_PKEY *pkey;
    std::vector<unsigned char> digest;
    std::vector<unsigned char> padding_val;
    std::unique_ptr<IEngine> pFactory;
    if (tbslen > tbsValueLen) {
        ENGINE_LOG(ERROR, "tbslen over length.");
        goto cleanup;
    }
    pFactory = EngineFactory::Create();
    if (pFactory == nullptr) {
        ENGINE_LOG(ERROR, "Create engine fail.");
        goto cleanup;
    }
    if ((pkey = EVP_PKEY_CTX_get0_pkey(ctx))) {
        size = EVP_PKEY_size(pkey);
    }
    EVP_PKEY_CTX_get_signature_md(ctx, &sigmd);
    EVP_PKEY_CTX_get_rsa_padding(ctx, &padding);
    digest.assign(tbs, tbs + tbslen);
    if (sigmd == nullptr) {
        sigmd = EVP_sha256();
    }
    switch (padding) {
        case RSA_NO_PADDING: {
            memcpy(tbsValue, tbs, tbslen);
            tbsValueLen = tbslen;
        }
            break;
        case RSA_PKCS1_PADDING: {
            padding_val = RsaUtils::EncodeDigestInfo(EVP_MD_nid(sigmd), digest);
            RSA_padding_add_PKCS1_type_1(tbsValue, size, padding_val.data(),
                                         (int) padding_val.size());
            tbsValueLen = size;
        }
            break;
        case RSA_PKCS1_PSS_PADDING: {
            const RSA *rsa = EVP_PKEY_get0_RSA(pkey);
            if (rsa) {
                RSA_padding_add_PKCS1_PSS((RSA *)rsa, tbsValue, digest.data(),
                                          sigmd, (int)digest.size());
                tbsValueLen = size;
            }
        }
            break;
        default:
            break;
    }
    if (pFactory->RsaPrivateKeyCalc(
            nullptr,
            (unsigned char *)tbsValue, tbsValueLen,
            pucDataOut, &puiDataOutLen) != 0) {
        ENGINE_LOG(ERROR, "RsaPrivateKeyCalc fail, fail code: " << rv);
        goto cleanup;
    }

    if (sig)    memcpy(sig, pucDataOut, puiDataOutLen);
    if (siglen) *siglen = puiDataOutLen;
    rv = 1;
cleanup:
    return rv;
}

int engine_rsa_method_verify(EVP_PKEY_CTX *ctx,
                             const unsigned char *sig,
                             size_t siglen,
                             const unsigned char *tbs,
                             size_t tbslen)
{
#if ENGINE_DEBUG
    fprintf(stdout, "%s\n", __func__);
#endif
    EVP_PKEY *pkey;
    const EVP_PKEY_METHOD *method;
    // default rsa method.
    int (*verify_init) (EVP_PKEY_CTX *ctx);
    int (*verify) (EVP_PKEY_CTX *, const unsigned char *, size_t, const unsigned char *, size_t);
    if (ctx == nullptr) {
        ENGINE_LOG(ERROR, "ctx is nullptr.");
        return -1;
    }
    pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    if (pkey == nullptr) {
        ENGINE_LOG(ERROR, "pkey is nullptr.");
        return -1;
    }
    method = EVP_PKEY_meth_find(EVP_PKEY_base_id(pkey));
    if (method == nullptr) {
        ENGINE_LOG(ERROR, "method is nullptr.");
        return -1;
    }
    EVP_PKEY_meth_get_verify(method, &verify_init, &verify);
    if (verify == nullptr) {
        ENGINE_LOG(ERROR, "verify is nullptr.");
        return -1;
    }
    return verify(ctx, sig, siglen, tbs, tbslen);
}

int engine_rsa_method_default_digestsign(EVP_MD_CTX *ctx,
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
    return ::engine_rsa_method_default_sign(pkeyctx, sig, siglen, md, mdSize);
}

int engine_rsa_method_digestsign(EVP_MD_CTX *ctx,
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
    return engine_rsa_method_sign(pkeyctx, sig, siglen, md, mdSize);
}

int engine_rsa_method_digestverify(EVP_MD_CTX *ctx,
                                   const unsigned char *sig, size_t siglen,
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
    return engine_rsa_method_verify(pkeyctx, sig, siglen, md, mdSize);
}

// Cipher message
// calling soft method
int engine_rsa_method_encrypt(EVP_PKEY_CTX *ctx,
                              unsigned char *out, size_t *outlen,
                              const unsigned char *in, size_t inlen)
{
#if ENGINE_DEBUG
    fprintf(stdout, "%s\n", __func__);
#endif
    int size = 256;
    const EVP_PKEY_METHOD *method;
    EVP_PKEY *pkey;
    int nid = EVP_PKEY_RSA;
    int (*encrypt_init)(EVP_PKEY_CTX *ctx);
    int (*encrypt)(EVP_PKEY_CTX *, unsigned char *,
                   size_t *, const unsigned char *, size_t);

    if (ctx == nullptr) {
        ENGINE_LOG(ERROR, "Parameter fail.");
        return -1;
    }
    if ((pkey = EVP_PKEY_CTX_get0_pkey(ctx))) {
        nid = EVP_PKEY_base_id(pkey);
        size = EVP_PKEY_size(pkey);
    }
    if (out == nullptr) {
        *outlen = size;
        return 1;
    }
    if (!(method = EVP_PKEY_meth_find(nid))) {
        ENGINE_LOG(ERROR, "EVP_PKEY_meth_find fail.");
        return -1;
    }
    EVP_PKEY_meth_get_encrypt(method, &encrypt_init, &encrypt);
    if (encrypt == nullptr) {
        ENGINE_LOG(ERROR, "EVP_PKEY_meth_get_encrypt fail.");
    }
    return encrypt(ctx, out, outlen, in, inlen);
}

// calling soft method
int engine_rsa_method_default_decrypt(EVP_PKEY_CTX *ctx,
                                      unsigned char *out, size_t *outlen,
                                      const unsigned char *in, size_t inlen)
{
#if ENGINE_DEBUG
    fprintf(stdout, "%s\n", __func__);
#endif
    int size = 256, nid = EVP_PKEY_RSA;
    EVP_PKEY *pkey;
    const EVP_PKEY_METHOD *method;
    std::vector<unsigned char> digest;
    std::vector<unsigned char> padding_val;
    int (*decrypt_init) (EVP_PKEY_CTX *ctx);
    int (*decrypt) (EVP_PKEY_CTX *, unsigned char *, size_t *,
                    const unsigned char *, size_t);

    if (ctx == nullptr || in == nullptr) {
        ENGINE_LOG(ERROR, "Parameter fail.");
        return -1;
    }
    if ((pkey = EVP_PKEY_CTX_get0_pkey(ctx))) {
        nid  = EVP_PKEY_base_id(pkey);
        size = EVP_PKEY_size(pkey);
    }
    if (out == nullptr) {
        *outlen = size;
        return 1;
    }
    method = EVP_PKEY_meth_find(nid);
    if (method == nullptr) {
        ENGINE_LOG(ERROR, "EVP_PKEY_meth_find fail.");
        return -1;
    }
    EVP_PKEY_meth_get_decrypt(method, &decrypt_init, &decrypt);
    if (decrypt == nullptr) {
        ENGINE_LOG(ERROR, "EVP_PKEY_meth_get_decrypt fail.");
        return -1;
    }
    return decrypt(ctx, out, outlen, in, inlen);
}

// calling hardware method
int engine_rsa_method_decrypt(EVP_PKEY_CTX *ctx,
                              unsigned char *out, size_t *outlen,
                              const unsigned char *in, size_t inlen)
{
#if ENGINE_DEBUG
    fprintf(stdout, "%s\n", __func__);
#endif
    int rv = -1, size = 0, len;
    EVP_PKEY *pkey;
    std::vector<unsigned char> digest;
    std::vector<unsigned char> padding_val;
    unsigned char *dstValue = nullptr;
    unsigned int dstValueLen = 0;
    std::unique_ptr<IEngine> pFactory;

    if (ctx == nullptr || in == nullptr) {
        ENGINE_LOG(ERROR, "Parameter fail.");
        return -1;
    }
    pFactory = EngineFactory::Create();
    if (pFactory == nullptr) {
        ENGINE_LOG(ERROR, "Create engine fail.");
        goto cleanup;
    }
    if ((pkey = EVP_PKEY_CTX_get0_pkey(ctx))) {
        size = EVP_PKEY_size(pkey);
    }
    if ((int)inlen != size) {
        ENGINE_LOG(ERROR, "Cipher length fail, inlen: " << inlen << "size: " << size);
        goto cleanup;
    }
    dstValueLen = size;
    if (!(dstValue = (unsigned char *)OPENSSL_zalloc(size))) {
        ENGINE_LOG(ERROR, "OPENSSL_zalloc fail");
        goto cleanup;
    }
    if (pFactory->RsaPrivateKeyCalc(nullptr,
                                   (unsigned char *)in, inlen,
                                   dstValue, &dstValueLen) != 0) {
        ENGINE_LOG(ERROR, "RsaPrivateKeyCalc fail, fail code: " << rv);
        goto cleanup;
    }
    len = RSA_padding_check_PKCS1_type_2(dstValue, (int)dstValueLen, dstValue,
                                         (int)dstValueLen, size);
    if (len < 0) {
        ENGINE_LOG(ERROR, "RSA_padding_check_PKCS1_type_2 fail, fail code: " << rv);
        goto cleanup;
    }
    if (out)    memcpy(out, dstValue, len);
    if (outlen) *outlen = len;
    rv = 1;
cleanup:
    OPENSSL_free(dstValue);
    return rv;
}