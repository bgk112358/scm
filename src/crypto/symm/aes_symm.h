// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_AES_SYMM_H
#define CYBERLIB_BUILD_AES_SYMM_H


#include "isymm.h"

namespace cyber {

class AesSymm : public ISymm {
public:

    AesSymm();
    ~AesSymm() override;

    std::string GetAlgorithmName() override;

    bool Init(
            Mode mode,
            unsigned char *pucKey,
            unsigned int  uiKeyLen,
            unsigned char *pucIV,
            unsigned int  uiIVLen,
            unsigned int uiEncOrDec,
            bool padding) override;

    bool Update(const std::vector<unsigned char>& vInData,
                std::vector<unsigned char>& vOutData) override;

    bool Final(std::vector<unsigned char>& vOutData) override;

    bool Compute(const std::vector<unsigned char> &vInData,
                 std::vector<unsigned char> &vOutData) override;

};

}

#endif //CYBERLIB_BUILD_AES_SYMM_H
