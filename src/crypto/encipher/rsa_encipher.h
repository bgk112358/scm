// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_RSA_ENCIPHER_H
#define CYBERLIB_BUILD_RSA_ENCIPHER_H

#include "iencipher.h"

namespace cyber {

class RsaEncipher : public IEncipher {

    // Encrypt Data
    bool EncryptData(
            IKeyPair *keyPair,
            const std::vector<uint8_t> &plainData,
            std::vector<uint8_t> &cipherData) override;

    // Decrypt Data
    bool DecryptData(
            IKeyPair *keyPair,
            const std::vector<uint8_t> &cipherData,
            std::vector<uint8_t> &plainData) override;

};

}


#endif //CYBERLIB_BUILD_RSA_ENCIPHER_H
