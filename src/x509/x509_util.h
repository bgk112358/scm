// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef SVKD_BUILD_X509_UTIL_H
#define SVKD_BUILD_X509_UTIL_H

#include <string>
#include <openssl/evp.h>

const uint32_t kSerialNumber = 111;
const uint32_t kTimeSecondsPerYear = 31536000L;

namespace cyber {
class X509Utils {
public:
    typedef enum {
        SHA256,
        SHA512,
        SM3
    } DigestAlgorithm;
    static bool CreateSelfSignCert(EVP_PKEY *pkey,
                                   DigestAlgorithm digestAlgorithm,
                                   std::string *psCertificate);
};
}



#endif //SVKD_BUILD_X509_UTIL_H
