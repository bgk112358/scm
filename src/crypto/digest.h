// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_DIGEST_H
#define CYBERLIB_BUILD_DIGEST_H

#include <memory>

#include "digest/idigest.h"

namespace cyber {

class Digest {
public:
    std::shared_ptr<IDigest> ptr;
    static IDigest *CreateDigest(const std::string & sAlgorithm);

};

}


#endif //CYBERLIB_BUILD_DIGEST_H
