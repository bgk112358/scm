// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "asymmetric_signer.h"
#include "util/string_utils.h"

using namespace cyber;

AsymmetricSigner::ptr
AsymmetricSigner::CreateSigner(const std::string &sAlgorithm) {
    std::shared_ptr<ISigner> iSigner;
    if (StringUtils::StartWith(sAlgorithm, "RSA"))
    {
        iSigner = std::make_shared<RsaSigner>();
    }
    else if (StringUtils::StartWith(sAlgorithm, "EC"))
    {
        iSigner = std::make_shared<EcdsaSigner>();
    }
    else if (StringUtils::StartWith(sAlgorithm, "SM2"))
    {
        iSigner = std::make_shared<Sm2Signer>();
    }
    else if (StringUtils::StartWith(sAlgorithm, "ED25519"))
    {
        iSigner = std::make_shared<Ed25519Signer>();
    }
    else
    {
        fprintf(stderr, "%s, UnSupport Algorithm: %s\n", __FUNCTION__,
                sAlgorithm.c_str());
    }
    return iSigner;
}
