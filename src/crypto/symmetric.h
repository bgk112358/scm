// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_SYMMETRIC_H
#define CYBERLIB_BUILD_SYMMETRIC_H

#include <memory>
#include "symm/isymm.h"

namespace cyber {

class Symmetric {
public:
    typedef std::shared_ptr<ISymm> ptr;
    // Ptr
    static ISymm *CreateSymm(const std::string &sAlgorithm);
    // AutoPtr
    static Symmetric::ptr CreateSymmPtr(const std::string &sAlgorithm);
};

}

#endif //CYBERLIB_BUILD_SYMMETRIC_H
