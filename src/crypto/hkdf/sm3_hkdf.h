// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_SM3_HKDF_H
#define CYBERLIB_BUILD_SM3_HKDF_H

#include "ihkdf.h"

namespace cyber {

class Sm3Hkdf : public IHkdf {

    std::string GetAlgorithmName() override;

    int GetHkdfSize() override;

    bool Compute(const std::vector<unsigned char> &ikm,
                 const std::vector<unsigned char> &info,
                 const std::vector<unsigned char> &salt,
                 size_t derived_key_size,
                 std::vector<unsigned char> &digest) override;

};

}


#endif //CYBERLIB_BUILD_SM3_HKDF_H
