// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_ECDSA_SIGNER_H
#define CYBERLIB_BUILD_ECDSA_SIGNER_H

#include "isigner.h"

namespace cyber {

class EcdsaSigner : public ISigner {

    std::string GetAlgorithm() override;

    // Make signature
    bool MakeSignature(
            IKeyPair *keyPair,
            const std::string &hashAlgorithm,
            const std::vector<uint8_t> &vMessage,
            std::vector<uint8_t> &vSignature) override;

    // Verify signature
    bool VerifySignature(
            IKeyPair *keyPair,
            const std::string &hashAlgorithm,
            const std::vector<uint8_t> &vMessage,
            const std::vector<uint8_t> &vSignature) override;

};

}

#endif //CYBERLIB_BUILD_ECDSA_SIGNER_H
