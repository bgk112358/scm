// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_HKDF_H
#define CYBERLIB_BUILD_HKDF_H

#include <memory>
#include "hkdf/ihkdf.h"

namespace cyber {

class Hkdf {
public:
    typedef std::shared_ptr<IHkdf> ptr;
    static std::shared_ptr<IHkdf> CreateHkdf(const std::string &sAlgorithm);
};

}

#endif //CYBERLIB_BUILD_HKDF_H
