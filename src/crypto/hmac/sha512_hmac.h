// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_SHA512_HMAC_H
#define CYBERLIB_BUILD_SHA512_HMAC_H

#include "ihmac.h"

namespace cyber {

class Sha512Hmac: public IHmac {
public:
    ~Sha512Hmac();

    Sha512Hmac();

    std::string GetAlgorithmName() override;

    int GetHmacSize() override;

    bool Init(const unsigned char *key, unsigned int key_len) override;

    bool Update(const unsigned char *data, unsigned int len) override;

    bool Final(unsigned char *out, unsigned int *out_len) override;

private:
    void *context_ = nullptr;
};

}
#endif //CYBERLIB_BUILD_SHA512_HMAC_H
