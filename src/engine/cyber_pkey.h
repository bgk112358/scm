// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_cyber_PKEY_H
#define CYBERLIB_BUILD_cyber_PKEY_H

#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

const EVP_PKEY_METHOD *cyber_rsa();

const EVP_PKEY_METHOD *cyber_ecc();

const EVP_PKEY_METHOD *cyber_sm2();

void cyber_rsa_destory(void);

void cyber_ecc_destory(void);

void cyber_sm2_destory(void);


#ifdef __cplusplus
}
#endif

#endif //CYBERLIB_BUILD_cyber_PKEY_H
