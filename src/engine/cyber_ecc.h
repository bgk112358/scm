// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_CYBER_ECC_H
#define CYBERLIB_BUILD_CYBER_ECC_H

#include <openssl/evp.h>

// Generate keypair
int engine_ecc_method_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);

// Make signature
// calling soft method
int engine_ecc_method_default_sign(EVP_PKEY_CTX *ctx,
                                   uint8_t *sig, size_t *siglen,
                                   const uint8_t *tbs, size_t tbslen);

int engine_ecc_method_sign(EVP_PKEY_CTX *ctx,
                           uint8_t *sig, size_t *siglen,
                           const uint8_t *tbs, size_t tbslen);

int engine_ecc_method_default_digestsign(EVP_MD_CTX *ctx,
                                         unsigned char *sig, size_t *siglen,
                                         const unsigned char *tbs, size_t tbslen);

int engine_ecc_method_digestsign(EVP_MD_CTX *ctx,
                                 unsigned char *sig, size_t *siglen,
                                 const unsigned char *tbs, size_t tbslen);

int engine_ecc_method_verify(EVP_PKEY_CTX *ctx,
                             const unsigned char *sig, size_t siglen,
                             const unsigned char *tbs, size_t tbslen);

int engine_ecc_method_digestverify(EVP_MD_CTX *ctx,
                                   const unsigned char *sig, size_t siglen,
                                   const unsigned char *tbs, size_t tbslen);

#endif //CYBERLIB_BUILD_cyber_ECC_H
