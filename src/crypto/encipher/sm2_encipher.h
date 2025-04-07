// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_SM2_ENCIPHER_H
#define CYBERLIB_BUILD_SM2_ENCIPHER_H

#include "iencipher.h"

namespace cyber {

class Sm2Encipher: public IEncipher {

public:
    // Encrypt Data， Only support C1C3C2
    // C1 is point on the SM2 curve.
    // C3 is hash.
    // C2 is cipher value.
    bool EncryptData(
            IKeyPair *keyPair,
            const std::vector<uint8_t> &plainData,
            std::vector<uint8_t> &cipherData) override;

    // Decrypt Data， Only support C1C3C2
    bool DecryptData(
            IKeyPair *keyPair,
            const std::vector<uint8_t> &cipherData,
            std::vector<uint8_t> &plainData) override;
};

}

#endif //CYBERLIB_BUILD_SM2_ENCIPHER_H
