// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_IHKDF_H
#define CYBERLIB_BUILD_IHKDF_H

#include <string>
#include <vector>

namespace cyber {

class IHkdf {
public:
    virtual std::string GetAlgorithmName() = 0;

    virtual int GetHkdfSize() = 0;

    virtual bool Compute(const std::vector<unsigned char> &ikm,
                         const std::vector<unsigned char> &info,
                         const std::vector<unsigned char> &salt,
                         size_t derived_key_size,
                         std::vector<unsigned char> &digest) = 0;

protected:
    int key_size_ = 0;
};

}

#endif //CYBERLIB_BUILD_IHKDF_H
