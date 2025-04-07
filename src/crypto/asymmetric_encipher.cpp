// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "asymmetric_encipher.h"
#include "encipher/rsa_encipher.h"
#include "encipher/sm2_encipher.h"
#include "util/string_utils.h"

using namespace cyber;

AsymmetricEncipher::ptr
AsymmetricEncipher::CreateEncipher(const std::string &sAlgorithm) {
    AsymmetricEncipher::ptr iEncipher = nullptr;
    if (StringUtils::StartWith(sAlgorithm, "RSA"))
    {
        iEncipher = std::make_shared<RsaEncipher>();
    }
    else if (StringUtils::StartWith(sAlgorithm, "SM2"))
    {
        iEncipher = std::make_shared<Sm2Encipher>();
    }
    else
    {
        fprintf(stderr, "%s, UnSupport Algorithm: %s\n", __FUNCTION__,
                sAlgorithm.c_str());
    }
    return iEncipher;
}
