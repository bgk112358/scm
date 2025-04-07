// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "symmetric.h"
#include "symm/aes_symm.h"
#include "symm/sm4_symm.h"
#include "symm/zuc_symm.h"
#include "util/string_utils.h"

using namespace cyber;

ISymm *Symmetric::CreateSymm(const std::string &sAlgorithm) {
    ISymm *iSymm = nullptr;
    if (StringUtils::StartWith(sAlgorithm, "AES")) {
        iSymm = new AesSymm();
    } else if (StringUtils::StartWith(sAlgorithm, "SM4")) {
        iSymm = new Sm4Symm();
    } else if (StringUtils::StartWith(sAlgorithm, "ZUC")) {
        iSymm = new ZucSymm();
    } else {
        fprintf(stderr, "%s, UnSupport Algorithm: %s", __FUNCTION__,
                sAlgorithm.c_str());
    }
    return iSymm;
}

Symmetric::ptr Symmetric::CreateSymmPtr(const std::string &sAlgorithm) {
   Symmetric::ptr iSymm = nullptr;
    if (StringUtils::StartWith(sAlgorithm, "AES")) {
        iSymm = std::make_shared<AesSymm>();
    } else if (StringUtils::StartWith(sAlgorithm, "SM4")) {
        iSymm = std::make_shared<Sm4Symm>();
    } else if (StringUtils::StartWith(sAlgorithm, "ZUC")) {
        iSymm = std::make_shared<ZucSymm>();
    } else {
        fprintf(stderr, "%s, UnSupport Algorithm: %s", __FUNCTION__,
                sAlgorithm.c_str());
    }
    return iSymm;
}
