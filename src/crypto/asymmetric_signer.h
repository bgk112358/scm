// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_ASYMMETRIC_SIGNER_H
#define CYBERLIB_BUILD_ASYMMETRIC_SIGNER_H

#include <memory>
#include "signers/rsa_signer.h"
#include "signers/ecdsa_signer.h"
#include "signers/sm2_signer.h"
#include "signers/ed25519_signer.h"

namespace cyber {

class AsymmetricSigner {

public:
    typedef std::shared_ptr<ISigner> ptr;
    static AsymmetricSigner::ptr CreateSigner(const std::string &sAlgorithm);
};

}

#endif //CYBERLIB_BUILD_ASYMMETRIC_SIGNER_H
