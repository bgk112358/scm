// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_ENGINE_H
#define CYBERLIB_BUILD_ENGINE_H

#include <openssl/rsa.h>

#ifdef __cplusplus
extern "C" {
#endif

void ENGINE_load_cyber();

void ENGINE_unload_cyber();

#ifdef __cplusplus
}
#endif

#endif //CYBERLIB_BUILD_ENGINE_H
