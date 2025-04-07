// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_IDIGEST_H
#define CYBERLIB_BUILD_IDIGEST_H

#include <string>

namespace cyber {

class IDigest {
public:
    virtual ~IDigest() = default;

    // algorithm name.
    virtual std::string GetAlgorithmName() = 0;

    // digest size.
    virtual int GetDigestSize() = 0;

    // init
    virtual bool Init() = 0;

    // update message.
    virtual bool Update(const unsigned char *data, unsigned int len) = 0;

    // final the hash with data.
    virtual bool Final(unsigned char *out, unsigned int *out_len) = 0;

    // Compute
    virtual bool Compute(const unsigned char *ucInData, unsigned int uiInDataLen,
                         unsigned char *ucOutData, unsigned int *uiOutDataLen) = 0;

};

}


#endif //CYBERLIB_BUILD_IDIGEST_H
