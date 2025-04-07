//
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//

#include "hmac.h"
#include "hmac/sm3_hmac.h"
#include "hmac/sha1_hmac.h"
#include "hmac/sha256_hmac.h"
#include "hmac/sha512_hmac.h"
#include "util/string_utils.h"

namespace cyber {

HMAC::ptr HMAC::CreateHmac(const std::string &sAlgorithm) {
    HMAC::ptr iHmac = nullptr;
    if (StringUtils::StartWith(sAlgorithm, "SM3"))
    {
        iHmac = std::make_shared<Sm3Hmac>();
    }
    else if (StringUtils::StartWith(sAlgorithm, "SHA1"))
    {
        iHmac = std::make_shared<Sha1Hmac>();
    }
    else if (StringUtils::StartWith(sAlgorithm, "SHA256"))
    {
        iHmac = std::make_shared<Sha256Hmac>();
    }
    else if (StringUtils::StartWith(sAlgorithm, "SHA512"))
    {
        iHmac = std::make_shared<Sha512Hmac>();
    }
    else
    {
        fprintf(stderr, "%s, UnSupport Algorithm: %s", __FUNCTION__,
                sAlgorithm.c_str());
    }
    return iHmac;
}

}