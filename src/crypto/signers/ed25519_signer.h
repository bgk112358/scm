// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_ED25519_SIGNER_H
#define CYBERLIB_BUILD_ED25519_SIGNER_H

#include "isigner.h"

namespace cyber {

class Ed25519Signer : public ISigner {

    std::string GetAlgorithm() override;

    bool MakeSignature(
            IKeyPair* keyPair,
            const std::string& sHashAlgorithm,
            const std::vector<uint8_t>& vMessage,
            std::vector<uint8_t>& vSignature) override;

    bool VerifySignature(
            IKeyPair* keyPair,
            const std::string& sHashAlgorithm,
            const std::vector<uint8_t>& vMessage,
            const std::vector<uint8_t>& vSignature) override;

};

}


#endif //CYBERLIB_BUILD_ED25519_SIGNER_H
