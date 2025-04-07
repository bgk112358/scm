// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_IHMAC_H
#define CYBERLIB_BUILD_IHMAC_H

#include <string>

namespace cyber {

class IHmac {

public:

    ~IHmac() = default;

    // algorithm name.
    virtual std::string GetAlgorithmName() = 0;

    // digest size.
    virtual int GetHmacSize() = 0;

    // init
    virtual bool Init(const unsigned char *key, unsigned int key_len) = 0;

    // update data
    virtual bool Update(const unsigned char *data, unsigned int data_len) = 0;

    // final the mac with data
    virtual bool Final(unsigned char *out, unsigned int *out_len) = 0;
};

}


#endif //CYBERLIB_BUILD_IHMAC_H
