// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "cyber_pkey.h"
#include <openssl/evp.h>
#include "cyber_rsa.h"
#include "cyber_ecc.h"
#include "cyber_sm2.h"

static EVP_PKEY_METHOD *cyber_rsa_method = nullptr;
static EVP_PKEY_METHOD *cyber_ec_method  = nullptr;
static EVP_PKEY_METHOD *cyber_sm2_method  = nullptr;
static EVP_PKEY_METHOD *cyber_prf_method  = nullptr;


/* RSA */
static int cyber_rsa_keygen(EVP_PKEY_CTX *ctx,
                            EVP_PKEY *pkey) {
    return engine_rsa_method_keygen(ctx, pkey);
}

static int cyber_rsa_sign(EVP_PKEY_CTX *ctx,
                          uint8_t *sig,
                          size_t *siglen,
                          const uint8_t *tbs,
                          size_t tbslen) {
    int rv = EVP_PKEY_check(ctx);
    if (rv == 1) {
        return engine_rsa_method_default_sign(ctx, sig, siglen, tbs, tbslen);
    }
    return engine_rsa_method_sign(ctx, sig, siglen, tbs, tbslen);
}

static int cyber_rsa_verify(EVP_PKEY_CTX *ctx,
                            const unsigned char *sig,
                            size_t siglen,
                            const unsigned char *tbs,
                            size_t tbslen) {
    return engine_rsa_method_verify(ctx, sig, siglen, tbs, tbslen);
}

static int cyber_rsa_digestsign(EVP_MD_CTX *ctx,
                                unsigned char *sig,
                                size_t *siglen,
                                const unsigned char *tbs,
                                size_t tbslen) {
    EVP_PKEY_CTX *pctx = EVP_MD_CTX_pkey_ctx(ctx);
    if (pctx == nullptr) {
        return -1;
    }
    int rv = EVP_PKEY_check(pctx);
    if (rv == 1) {
        return engine_rsa_method_default_digestsign(ctx, sig, siglen, tbs, tbslen);
    }
    return engine_rsa_method_digestsign(ctx, sig, siglen, tbs, tbslen);
}

static int cyber_rsa_digestverify(EVP_MD_CTX *ctx,
                                  const unsigned char *sig,
                                  size_t siglen,
                                  const unsigned char *tbs,
                                  size_t tbslen) {
    return engine_rsa_method_digestverify(ctx, sig, siglen, tbs, tbslen);
}

static int cyber_rsa_decrypt(EVP_PKEY_CTX *ctx,
                             unsigned char *out,
                             size_t *outlen,
                             const unsigned char *in,
                             size_t inlen) {
    int rv = EVP_PKEY_check(ctx);
    if (rv == 1) {
        return engine_rsa_method_default_decrypt(ctx, out, outlen, in, inlen);
    }
    return engine_rsa_method_decrypt(ctx, out, outlen, in, inlen);
}

static int cyber_rsa_encrypt(EVP_PKEY_CTX *ctx,
                             unsigned char *out,
                             size_t *outlen,
                             const unsigned char *in,
                             size_t inlen) {
    return engine_rsa_method_encrypt(ctx, out, outlen, in, inlen);
}

/* ECC */
static int cyber_ec_keygen(EVP_PKEY_CTX *ctx,
                           EVP_PKEY *pkey) {
    return engine_ecc_method_keygen(ctx, pkey);
}

static int cyber_ec_sign(EVP_PKEY_CTX *ctx,
                         uint8_t *sig,
                         size_t *siglen,
                         const uint8_t *tbs,
                         size_t tbslen) {
    return engine_ecc_method_sign(ctx, sig, siglen, tbs, tbslen);
}

static int cyber_ec_digestsign(EVP_MD_CTX *ctx,
                               unsigned char *sig,
                               size_t *siglen,
                               const unsigned char *tbs,
                               size_t tbslen) {
    return engine_ecc_method_digestsign(ctx, sig, siglen, tbs, tbslen);
}

static int cyber_ec_verify(EVP_PKEY_CTX *ctx,
                           const unsigned char *sig,
                           size_t siglen,
                           const unsigned char *tbs,
                           size_t tbslen) {
    return engine_ecc_method_verify(ctx, sig, siglen, tbs, tbslen);
}

static int cyber_ec_digestverify(EVP_MD_CTX *ctx,
                                 const unsigned char *sig,
                                 size_t siglen,
                                 const unsigned char *tbs,
                                 size_t tbslen) {
    return engine_ecc_method_digestverify(ctx, sig, siglen, tbs, tbslen);
}

/* SM2 */
static int cyber_sm2_keygen(EVP_PKEY_CTX *ctx,
                           EVP_PKEY *pkey) {
    return engine_sm2_method_keygen(ctx, pkey);
}

static int cyber_sm2_sign(EVP_PKEY_CTX *ctx,
                         uint8_t *sig,
                         size_t *siglen,
                         const uint8_t *tbs,
                         size_t tbslen) {
    return engine_sm2_method_sign(ctx, sig, siglen, tbs, tbslen);
}

static int cyber_sm2_digestsign(EVP_MD_CTX *ctx,
                               unsigned char *sig,
                               size_t *siglen,
                               const unsigned char *tbs,
                               size_t tbslen) {
    return engine_sm2_method_digestsign(ctx, sig, siglen, tbs, tbslen);
}

static int cyber_sm2_verify(EVP_PKEY_CTX *ctx,
                           const unsigned char *sig,
                           size_t siglen,
                           const unsigned char *tbs,
                           size_t tbslen) {
    return engine_sm2_method_verify(ctx, sig, siglen, tbs, tbslen);
}

static int cyber_sm2_digestverify(EVP_MD_CTX *ctx,
                                 const unsigned char *sig,
                                 size_t siglen,
                                 const unsigned char *tbs,
                                 size_t tbslen) {
    return engine_sm2_method_digestverify(ctx, sig, siglen, tbs, tbslen);
}

static int cyber_sm2_method_decrypt(EVP_PKEY_CTX *ctx,
                                  unsigned char *out, size_t *outlen,
                                  const unsigned char *in, size_t inlen) {
    return engine_sm2_method_decrypt(ctx, out, outlen, in, inlen);
}

/* PKEY METHOD */
const EVP_PKEY_METHOD *cyber_rsa()
{
    const EVP_PKEY_METHOD *default_method = EVP_PKEY_meth_find(EVP_PKEY_RSA);
    if (cyber_rsa_method != nullptr)
        goto ret;
    // FBI WARNING. Can`t use EVP_PKEY_FLAG_SIGCTX_CUSTOM
    cyber_rsa_method = EVP_PKEY_meth_new(EVP_PKEY_RSA, EVP_PKEY_FLAG_AUTOARGLEN);
    if (cyber_rsa_method == nullptr)
        goto ret;
    if (default_method)
        EVP_PKEY_meth_copy(cyber_rsa_method, default_method);

    EVP_PKEY_meth_set_keygen(cyber_rsa_method, nullptr, cyber_rsa_keygen);
    EVP_PKEY_meth_set_sign(cyber_rsa_method, nullptr, cyber_rsa_sign);
    EVP_PKEY_meth_set_verify(cyber_rsa_method, nullptr, cyber_rsa_verify);
    EVP_PKEY_meth_set_digestsign(cyber_rsa_method, cyber_rsa_digestsign);
    EVP_PKEY_meth_set_digestverify(cyber_rsa_method, cyber_rsa_digestverify);
    EVP_PKEY_meth_set_decrypt(cyber_rsa_method, nullptr, cyber_rsa_decrypt);
    EVP_PKEY_meth_set_encrypt(cyber_rsa_method, nullptr, cyber_rsa_encrypt);
ret:
    return cyber_rsa_method;
}

const EVP_PKEY_METHOD *cyber_ecc()
{
    const EVP_PKEY_METHOD *default_method = EVP_PKEY_meth_find(EVP_PKEY_EC);
    if (cyber_ec_method != nullptr)
        goto ret;
    cyber_ec_method = EVP_PKEY_meth_new(EVP_PKEY_EC, EVP_PKEY_FLAG_AUTOARGLEN);
    if (cyber_ec_method == nullptr)
        goto ret;
    if (default_method)
        EVP_PKEY_meth_copy(cyber_ec_method, default_method);

    EVP_PKEY_meth_set_keygen(cyber_ec_method, nullptr, cyber_ec_keygen);
    EVP_PKEY_meth_set_sign(cyber_ec_method, nullptr, cyber_ec_sign);
    EVP_PKEY_meth_set_digestsign(cyber_ec_method, cyber_ec_digestsign);
    EVP_PKEY_meth_set_verify(cyber_ec_method, nullptr, cyber_ec_verify);
    EVP_PKEY_meth_set_digestverify(cyber_ec_method, cyber_ec_digestverify);
ret:
    return cyber_ec_method;
}
typedef int (*pkey_digest_custom_func)(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);

int gmssl_engine_pkey_verify_digest_custom(EVP_PKEY_CTX *ctx,
                                           EVP_MD_CTX *mctx) {
//    printf("------ Verify Digest Custom \n");
    pkey_digest_custom_func default_verify = nullptr;
    EVP_PKEY_METHOD *pmeth = (EVP_PKEY_METHOD *)EVP_PKEY_meth_find(EVP_PKEY_SM2);
    EVP_PKEY_meth_get_digest_custom(pmeth, &default_verify);
    return (*default_verify)(ctx, mctx);
//    return 1;
}

const EVP_PKEY_METHOD *cyber_sm2()
{
    const EVP_PKEY_METHOD *default_method = EVP_PKEY_meth_find(EVP_PKEY_SM2);
    if (cyber_sm2_method != nullptr)
        goto ret;
    cyber_sm2_method = EVP_PKEY_meth_new(EVP_PKEY_SM2, EVP_PKEY_FLAG_AUTOARGLEN);
    if (cyber_sm2_method == nullptr)
        goto ret;
    if (default_method)
        EVP_PKEY_meth_copy(cyber_sm2_method, default_method);

    EVP_PKEY_meth_set_keygen(cyber_sm2_method, nullptr, cyber_sm2_keygen);
    EVP_PKEY_meth_set_sign(cyber_sm2_method, nullptr, cyber_sm2_sign);
    EVP_PKEY_meth_set_digestsign(cyber_sm2_method, cyber_sm2_digestsign);
    EVP_PKEY_meth_set_verify(cyber_sm2_method, nullptr, cyber_sm2_verify);
    EVP_PKEY_meth_set_digestverify(cyber_sm2_method, cyber_sm2_digestverify);
    EVP_PKEY_meth_set_decrypt(cyber_sm2_method, nullptr, cyber_sm2_method_decrypt);

    EVP_PKEY_meth_set_digest_custom(cyber_sm2_method, gmssl_engine_pkey_verify_digest_custom);

ret:
    return cyber_sm2_method;
}

void cyber_rsa_destory(void)
{
    if (cyber_rsa_method != nullptr) {
        EVP_PKEY_meth_free(cyber_rsa_method);
        cyber_rsa_method = nullptr;
    }
}

void cyber_ecc_destory(void)
{
    if (cyber_ec_method != nullptr) {
        EVP_PKEY_meth_free(cyber_ec_method);
        cyber_ec_method = nullptr;
    }
}

void cyber_sm2_destory(void)
{
    if (cyber_sm2_method != nullptr) {
        EVP_PKEY_meth_free(cyber_sm2_method);
        cyber_sm2_method = nullptr;
    }
}