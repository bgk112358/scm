// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_SIGNER_H
#define CYBERLIB_BUILD_SIGNER_H

#include <vector>
#include "crypto/generators/ikeypair.h"

namespace cyber {

class ISigner {
public:
    typedef enum {
        PKCS1,
        PSS,
    } RsaPadding;
public:
    virtual ~ISigner() = default;
    // Padding Method
    void SetRsaPadding(RsaPadding padding) { padding_ = padding; }

    virtual std::string GetAlgorithm() = 0;

    // Make signature
    virtual bool MakeSignature(
            IKeyPair* keyPair,
            const std::string& sHashAlgorithm,
            const std::vector<uint8_t>& vMessage,
            std::vector<uint8_t>& vSignature) = 0;

    // Verify signature
    virtual bool VerifySignature(
            IKeyPair* keyPair,
            const std::string& sHashAlgorithm,
            const std::vector<uint8_t>& vMessage,
            const std::vector<uint8_t>& vSignature) = 0;

protected:
    RsaPadding padding_ = PKCS1;
};

}

#endif //CYBERLIB_BUILD_SIGNER_H
