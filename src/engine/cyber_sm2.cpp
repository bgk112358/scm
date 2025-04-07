// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "cyber_sm2.h"
#include "iengine.h"
#include "engine_factory.h"
#include "engine_utils.h"
#include "engine_config.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include "int_utils.h"
#include "cyber_sm3_preprocess.h"

using namespace cyber;

// Generate keypair
int engine_sm2_method_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
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
int engine_sm2_method_default_sign(EVP_PKEY_CTX *ctx,
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
int engine_sm2_method_sign(EVP_PKEY_CTX *ctx,
                           uint8_t *sig, size_t *siglen,
                           const uint8_t *tbs, size_t tbslen)
{
#if ENGINE_DEBUG
    fprintf(stdout, "%s\n", __func__);
#endif
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

int engine_sm2_method_default_digestsign(EVP_MD_CTX *ctx,
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
    return engine_sm2_method_default_sign(pkeyctx, sig, siglen, md, mdSize);
}

int engine_sm2_method_digestsign(EVP_MD_CTX *ctx,
                                 unsigned char *sig, size_t *siglen,
                                 const unsigned char *tbs, size_t tbslen)
{
#if ENGINE_DEBUG
    fprintf(stdout, "%s\n", __func__);
#endif
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
    return engine_sm2_method_sign(pkeyctx, sig, siglen, tbs, tbslen);
}

static int sm2_sig_verify(const EC_KEY *key, const ECDSA_SIG *sig,
                          const BIGNUM *e)
{
    int ret = 0;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    BN_CTX *ctx = NULL;
    EC_POINT *pt = NULL;
    BIGNUM *t = NULL;
    BIGNUM *x1 = NULL;
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;

    ctx = BN_CTX_new();
    pt = EC_POINT_new(group);
    if (ctx == NULL || pt == NULL) {
        ret = ERR_R_MALLOC_FAILURE;
        goto done;
    }

    BN_CTX_start(ctx);
    t = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    if (x1 == NULL) {
        ret = ERR_R_MALLOC_FAILURE;
        goto done;
    }

    /*
     * B1: verify whether r' in [1,n-1], verification failed if not
     * B2: verify whether s' in [1,n-1], verification failed if not
     * B3: set M'~=ZA || M'
     * B4: calculate e'=Hv(M'~)
     * B5: calculate t = (r' + s') modn, verification failed if t=0
     * B6: calculate the point (x1', y1')=[s']G + [t]PA
     * B7: calculate R=(e'+x1') modn, verification pass if yes, otherwise failed
     */

    ECDSA_SIG_get0(sig, &r, &s);

    if (BN_cmp(r, BN_value_one()) < 0
        || BN_cmp(s, BN_value_one()) < 0
        || BN_cmp(order, r) <= 0
        || BN_cmp(order, s) <= 0) {
        ret = -1;
        goto done;
    }

    if (!BN_mod_add(t, r, s, order, ctx)) {
        ret = ERR_R_BN_LIB;
        goto done;
    }

    if (BN_is_zero(t)) {
        ret = -2;
        goto done;
    }

    if (!EC_POINT_mul(group, pt, s, EC_KEY_get0_public_key(key), t, ctx)
        || !EC_POINT_get_affine_coordinates(group, pt, x1, NULL, ctx)) {
        ret = ERR_R_EC_LIB;
        goto done;
    }

    if (!BN_mod_add(t, e, x1, order, ctx)) {
        ret = ERR_R_BN_LIB;
        goto done;
    }

    if (BN_cmp(r, t) == 0)
        ret = 1;

done:
    EC_POINT_free(pt);
    BN_CTX_free(ctx);
    return ret;
}


static int sm2_verify(const unsigned char *dgst, int dgstlen,
               const unsigned char *sig, int sig_len, EC_KEY *eckey)
{
    ECDSA_SIG *s = NULL;
    BIGNUM *e = NULL;
    const unsigned char *p = sig;
    unsigned char *der = NULL;
    int derlen = -1;
    int ret = -1;

    s = ECDSA_SIG_new();
    if (s == NULL) {
        ret = ERR_R_MALLOC_FAILURE;
        goto done;
    }
    if (d2i_ECDSA_SIG(&s, &p, sig_len) == NULL) {
        ret = -1;
        goto done;
    }
    /* Ensure signature uses DER and doesn't have trailing garbage */
    derlen = i2d_ECDSA_SIG(s, &der);
    if (derlen != sig_len || memcmp(sig, der, derlen) != 0) {
        ret = -2;
        goto done;
    }

    e = BN_bin2bn(dgst, dgstlen, NULL);
    if (e == NULL) {
        ret = ERR_R_BN_LIB;
        goto done;
    }

    ret = sm2_sig_verify(eckey, s, e);

    done:
    OPENSSL_free(der);
    BN_free(e);
    ECDSA_SIG_free(s);
    return ret;
}

static int sm2_compute_z_digest(uint8_t *out,
                         const EVP_MD *digest,
                         const uint8_t *id,
                         const size_t id_len,
                         const EC_KEY *key)
{
    int rc = 0;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    BN_CTX *ctx = NULL;
    EVP_MD_CTX *hash = NULL;
    BIGNUM *p = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *xG = NULL;
    BIGNUM *yG = NULL;
    BIGNUM *xA = NULL;
    BIGNUM *yA = NULL;
    int p_bytes = 0;
    uint8_t *buf = NULL;
    uint16_t entl = 0;
    uint8_t e_byte = 0;

    hash = EVP_MD_CTX_new();
    ctx = BN_CTX_new();
    if (hash == NULL || ctx == NULL) {
        rc = ERR_R_MALLOC_FAILURE;
        goto done;
    }

    p = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    xG = BN_CTX_get(ctx);
    yG = BN_CTX_get(ctx);
    xA = BN_CTX_get(ctx);
    yA = BN_CTX_get(ctx);

    if (yA == NULL) {
        rc = ERR_R_MALLOC_FAILURE;
        goto done;
    }

    if (!EVP_DigestInit(hash, digest)) {
        rc = ERR_R_EVP_LIB;
        goto done;
    }

    /* Z = h(ENTL || ID || a || b || xG || yG || xA || yA) */

    if (id_len >= (UINT16_MAX / 8)) {
        /* too large */
        rc = -1;
        goto done;
    }

    entl = (uint16_t)(8 * id_len);

    e_byte = entl >> 8;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        rc = ERR_R_EVP_LIB;
        goto done;
    }
    e_byte = entl & 0xFF;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        rc = ERR_R_EVP_LIB;
        goto done;
    }

    if (id_len > 0 && !EVP_DigestUpdate(hash, id, id_len)) {
        rc = ERR_R_EVP_LIB;
        goto done;
    }

    if (!EC_GROUP_get_curve(group, p, a, b, ctx)) {
        rc = ERR_R_EC_LIB;
        goto done;
    }

    p_bytes = BN_num_bytes(p);
    buf = (unsigned char *)OPENSSL_zalloc(p_bytes);
    if (buf == NULL) {
        rc = ERR_R_MALLOC_FAILURE;
        goto done;
    }

    if (BN_bn2binpad(a, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || BN_bn2binpad(b, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || !EC_POINT_get_affine_coordinates(group,
                                            EC_GROUP_get0_generator(group),
                                            xG, yG, ctx)
        || BN_bn2binpad(xG, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || BN_bn2binpad(yG, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || !EC_POINT_get_affine_coordinates(group,
                                            EC_KEY_get0_public_key(key),
                                            xA, yA, ctx)
        || BN_bn2binpad(xA, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || BN_bn2binpad(yA, buf, p_bytes) < 0
        || !EVP_DigestUpdate(hash, buf, p_bytes)
        || !EVP_DigestFinal(hash, out, NULL)) {
        rc = ERR_R_INTERNAL_ERROR;
        goto done;
    }

    rc = 1;
done:
    OPENSSL_free(buf);
    BN_CTX_free(ctx);
    EVP_MD_CTX_free(hash);
    return rc;
}


static BIGNUM *sm2_compute_msg_hash(const EVP_MD *digest,
                                    const EC_KEY *key,
                                    const uint8_t *id,
                                    const size_t id_len,
                                    const uint8_t *msg, size_t msg_len)
{
    int rc = 0;
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    const int md_size = EVP_MD_size(digest);
    uint8_t *z = NULL;
    BIGNUM *e = NULL;

    if (md_size < 0) {
        rc = -1;
        goto done;
    }

    z = (uint8_t *)OPENSSL_zalloc(md_size);
    if (hash == NULL || z == NULL) {
        rc = ERR_R_MALLOC_FAILURE;
        goto done;
    }

    if (!sm2_compute_z_digest(z, digest, id, id_len, key)) {
        /* SM2err already called */
        goto done;
    }

    if (!EVP_DigestInit(hash, digest)
        || !EVP_DigestUpdate(hash, z, md_size)
        || !EVP_DigestUpdate(hash, msg, msg_len)
        /* reuse z buffer to hold H(Z || M) */
        || !EVP_DigestFinal(hash, z, NULL)) {
        rc = ERR_R_EVP_LIB;
        goto done;
    }

    e = BN_bin2bn(z, md_size, NULL);
    if (e == NULL)
        rc = ERR_R_INTERNAL_ERROR;

    done:
    OPENSSL_free(z);
    EVP_MD_CTX_free(hash);
    return e;
}

int engine_sm2_method_verify(EVP_PKEY_CTX *ctx,
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
    rv = sm2_verify(tbs, (int)tbslen, sig, (int)siglen, (EC_KEY *)ec_key);
    if (rv != 1) {
        ENGINE_LOG(ERROR, "ECDSA_verify fail.");
        ERR_print_errors_fp(stdout);
    }
cleanup:
#if ENGINE_DEBUG
    fprintf(stdout, "verify res: %d\n", rv);
#endif
    return rv;
}

int engine_sm2_method_digestverify(EVP_MD_CTX *ctx,
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
    const char *GMID = "1234567812345678";
    int GMIDLen = 16;
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
    unsigned char *pub_key_raw = nullptr;
    size_t pub_key_len = 0;

    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(pkeyctx);
    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ec_key) {
        // 错误处理
        return -1;
    }

    BIGNUM *be = sm2_compute_msg_hash(EVP_sm3(), ec_key, (const uint8_t *)GMID, (const size_t)GMIDLen, tbs, tbslen);

    mdSize = 32;

    BN_bn2binpad(be, md, mdSize);

    EC_KEY_free(ec_key);
    free(pub_key_raw);
    return engine_sm2_method_verify(pkeyctx, sig, siglen, md, mdSize);
}

int engine_sm2_method_decrypt(EVP_PKEY_CTX *ctx,
                              unsigned char *out, size_t *outlen,
                              const unsigned char *in, size_t inlen)
{
#if ENGINE_DEBUG
    fprintf(stdout, "%s\n", __func__);
#endif
    int rv = -1;
    unsigned char pucDataOut[256] = {0};
    unsigned int puiDataOutLen = 256;
    std::unique_ptr<IEngine> pFactory;
    if (ctx == nullptr || in == nullptr) {
        ENGINE_LOG(ERROR, "Parameter fail.");
        goto cleanup;
    }
    pFactory = EngineFactory::Create();
    if (pFactory == nullptr) {
        ENGINE_LOG(ERROR, "Create engine fail.");
        goto cleanup;
    }
    if (pFactory->EccDecrypt(
            nullptr, (unsigned char *)in, inlen, pucDataOut, &puiDataOutLen) != 0) {
        ENGINE_LOG(ERROR, "EccSign fail");
        goto cleanup;
    }
    if (out)    memcpy(out, pucDataOut, puiDataOutLen);
    if (outlen) *outlen = puiDataOutLen;
    rv = 1;
cleanup:
    return rv;
}