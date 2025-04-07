// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_SHA512_DIGEST_H
#define CYBERLIB_BUILD_SHA512_DIGEST_H

#include "idigest.h"

namespace cyber {

class Sha512Digest : public IDigest {
public:
    Sha512Digest();
    ~Sha512Digest() override;

    std::string GetAlgorithmName() override;

    int GetDigestSize() override;

    bool Init() override;

    bool Update(const unsigned char *data, unsigned int len) override;

    // The out buffer size must be greater than 64
    bool Final(unsigned char *out, unsigned int *out_len) override;

    bool Compute(const unsigned char *ucInData, unsigned int uiInDataLen,
                 unsigned char *ucOutData, unsigned int *uiOutDataLen) override;

private:
    void *context_ = nullptr;
};

}

#endif //CYBERLIB_BUILD_SHA512_DIGEST_H
