// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_ASYMMETRIC_ENCIPHER_H
#define CYBERLIB_BUILD_ASYMMETRIC_ENCIPHER_H

#include <memory>
#include "encipher/iencipher.h"

namespace cyber {

class AsymmetricEncipher {
public:
    typedef std::shared_ptr<IEncipher> ptr;
    static AsymmetricEncipher::ptr CreateEncipher(const std::string &sAlgorithm);

};

}

#endif //CYBERLIB_BUILD_ASYMMETRIC_ENCIPHER_H
