// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_CYBER_SM2_H
#define CYBERLIB_BUILD_CYBER_SM2_H

#include <openssl/evp.h>

int engine_sm2_method_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);

int engine_sm2_method_default_sign(EVP_PKEY_CTX *ctx,
                                   uint8_t *sig, size_t *siglen,
                                   const uint8_t *tbs, size_t tbslen);

int engine_sm2_method_sign(EVP_PKEY_CTX *ctx,
                           uint8_t *sig, size_t *siglen,
                           const uint8_t *tbs, size_t tbslen);

int engine_sm2_method_default_digestsign(EVP_MD_CTX *ctx,
                                         unsigned char *sig, size_t *siglen,
                                         const unsigned char *tbs, size_t tbslen);

int engine_sm2_method_digestsign(EVP_MD_CTX *ctx,
                                 unsigned char *sig, size_t *siglen,
                                 const unsigned char *tbs, size_t tbslen);

int engine_sm2_method_verify(EVP_PKEY_CTX *ctx,
                             const unsigned char *sig, size_t siglen,
                             const unsigned char *tbs, size_t tbslen);

int engine_sm2_method_digestverify(EVP_MD_CTX *ctx,
                                   const unsigned char *sig, size_t siglen,
                                   const unsigned char *tbs, size_t tbslen);


int engine_sm2_method_decrypt(EVP_PKEY_CTX *ctx,
                              unsigned char *out, size_t *outlen,
                              const unsigned char *in, size_t inlen);

#endif //CYBERLIB_BUILD_CYBER_SM2_H
