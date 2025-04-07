// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_SHA256_DIGEST_H
#define CYBERLIB_BUILD_SHA256_DIGEST_H

#include "idigest.h"

namespace cyber {

class Sha256Digest : public IDigest {
public:

    Sha256Digest();
    ~Sha256Digest() override;

    std::string GetAlgorithmName() override;

    int GetDigestSize() override;

    bool Init() override;

    bool Update(const unsigned char *data, unsigned int len) override;

    // The out buffer size must be greater than 32
    bool Final(unsigned char *out, unsigned int *out_len) override;

    bool Compute(const unsigned char *ucInData, unsigned int uiInDataLen,
                 unsigned char *ucOutData, unsigned int *uiOutDataLen) override;
private:
    void *context_ = nullptr;
};

}


#endif //CYBERLIB_BUILD_SHA256_DIGEST_H
