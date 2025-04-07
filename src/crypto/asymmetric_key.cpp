// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "asymmetric_key.h"
#include "generators/rsa_keypair.h"
#include "generators/ecc_keypair.h"
#include "util/string_utils.h"

using namespace cyber;

AsymmetricKey::ptr AsymmetricKey::CreateKeyPair(const std::string &sAlgorithm) {
    AsymmetricKey::ptr iKeyPair = nullptr;
    if (StringUtils::StartWith(sAlgorithm, "RSA"))
    {
        iKeyPair = std::make_shared<RsaKeyPair>();
    }
    else if (StringUtils::StartWith(sAlgorithm, "ECC") ||
             StringUtils::StartWith(sAlgorithm, "EC")  ||
             StringUtils::StartWith(sAlgorithm, "SM2") ||
             StringUtils::StartWith(sAlgorithm, "BRAINPOOL_P256R1"))
    {
        iKeyPair = std::make_shared<EccKeyPair>();
    }
    else
    {
        fprintf(stderr, "%s, UnSupport Algorithm: %s", __FUNCTION__,
                sAlgorithm.c_str());
    }
    return iKeyPair;
}