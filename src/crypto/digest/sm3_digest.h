// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_SM3_DIGEST_H
#define CYBERLIB_BUILD_SM3_DIGEST_H

#include "idigest.h"

#ifndef SM3_DIGEST_LENGTH
#define SM3_DIGEST_LENGTH 32
#endif

namespace cyber {

class Sm3Digest : public IDigest {
public:
    Sm3Digest();
    ~Sm3Digest() override;

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


#endif //CYBERLIB_BUILD_SM3_DIGEST_H
