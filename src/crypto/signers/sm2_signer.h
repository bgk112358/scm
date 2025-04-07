// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_SM2_SIGNER_H
#define CYBERLIB_BUILD_SM2_SIGNER_H

#include "isigner.h"

namespace cyber {

class Sm2Signer: public ISigner {

    std::string GetAlgorithm() override;

    bool MakeSignature(
            IKeyPair *keyPair,
            const std::string &hashAlgorithm,
            const std::vector<uint8_t> &vMessage,
            std::vector<uint8_t> &vSignature) override;

    bool VerifySignature(
            IKeyPair *keyPair,
            const std::string &hashAlgorithm,
            const std::vector<uint8_t> &vMessage,
            const std::vector<uint8_t> &vSignature) override;
};

}



#endif //CYBERLIB_BUILD_SM2_SIGNER_H
