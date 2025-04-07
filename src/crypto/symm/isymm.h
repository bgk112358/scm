// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_ISYMM_H
#define CYBERLIB_BUILD_ISYMM_H

#include <string>
#include <vector>

namespace cyber {

class ISymm {
public:
    typedef enum {
        NONE,
        ECB,
        CBC,
        CFB,
        OFB,
    } Mode;

    virtual ~ISymm() = default;

    virtual std::string GetAlgorithmName() = 0;

    virtual bool Init(
            Mode mode,
            unsigned char *pucKey,
            unsigned int  uiKeyLen,
            unsigned char *pucIV,
            unsigned int  uiIVLen,
            unsigned int uiEncOrDec,
            bool padding) = 0;

    virtual bool Update(const std::vector<unsigned char>& vInData,
                        std::vector<unsigned char>& vOutData) = 0;

    virtual bool Final(std::vector<unsigned char>& vOutData) = 0;

    virtual bool Compute(const std::vector<unsigned char>& vInData,
                         std::vector<unsigned char>& vOutData) = 0;

protected:
    unsigned int keybits_ = 0;
    Mode mode_ = NONE;

    void *context_ = nullptr;
};

}


#endif //CYBERLIB_BUILD_ISYMM_H
