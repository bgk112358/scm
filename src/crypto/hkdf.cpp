// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "hkdf.h"
#include "hkdf/sm3_hkdf.h"
#include "hkdf/sha1_hkdf.h"
#include "hkdf/sha256_hkdf.h"
#include "hkdf/sha512_hkdf.h"
#include "util/string_utils.h"

using namespace cyber;

std::shared_ptr<IHkdf> Hkdf::CreateHkdf(const std::string &sAlgorithm) {
    Hkdf::ptr iHkdf = nullptr;
    if (StringUtils::StartWith(sAlgorithm, "SM3"))
    {
        iHkdf = std::make_shared<Sm3Hkdf>();
    }
    else if (StringUtils::StartWith(sAlgorithm, "SHA1"))
    {
        iHkdf = std::make_shared<Sha1Hkdf>();
    }
    else if (StringUtils::StartWith(sAlgorithm, "SHA256"))
    {
        iHkdf = std::make_shared<Sha256Hkdf>();
    }
    else if (StringUtils::StartWith(sAlgorithm, "SHA512"))
    {
        iHkdf = std::make_shared<Sha512Hkdf>();
    } else {
        fprintf(stderr, "%s, UnSupport Algorithm: %s", __FUNCTION__,
                sAlgorithm.c_str());
    }
    return iHkdf;
}
