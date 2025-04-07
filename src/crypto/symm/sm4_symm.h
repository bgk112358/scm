// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_SM4_SYMM_H
#define CYBERLIB_BUILD_SM4_SYMM_H

#include "isymm.h"

namespace cyber {

class Sm4Symm : public ISymm {
public:

    Sm4Symm();
    ~Sm4Symm() override;

    std::string GetAlgorithmName() override;

    bool Init(
            Mode mode,
            unsigned char *pucKey,
            unsigned int  uiKeyLen,
            unsigned char *pucIV,
            unsigned int  uiIVLen,
            unsigned int uiEncOrDec,
            bool padding) override;

    bool Update(const std::vector<unsigned char>& sInData,
                std::vector<unsigned char>& sOutData) override;

    bool Final(std::vector<unsigned char>& sOutData) override;

    bool Compute(const std::vector<unsigned char> &vInData,
                 std::vector<unsigned char> &vOutData) override;
};

}



#endif //CYBERLIB_BUILD_SM4_SYMM_H
