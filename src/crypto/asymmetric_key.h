// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef SVKD_BUILD_ASYMMETRIC_KEY_H
#define SVKD_BUILD_ASYMMETRIC_KEY_H

#include <memory>
#include "generators/ikeypair.h"

namespace cyber {

class AsymmetricKey {
public:
    typedef std::shared_ptr<IKeyPair> ptr;
    static AsymmetricKey::ptr CreateKeyPair(const std::string &sAlgorithm);
};

}


#endif //SVKD_BUILD_ASYMMETRIC_KEY_H
