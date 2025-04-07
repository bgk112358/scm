// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_IENCIPHER_H
#define CYBERLIB_BUILD_IENCIPHER_H

#include <vector>
#include "../generators/ikeypair.h"

namespace cyber {

class IEncipher {

public:

    // destructor function
    virtual ~IEncipher() = default;

    // Encrypt Data
    virtual bool EncryptData(
            IKeyPair* keyPair,
            const std::vector<uint8_t>& plainData,
            std::vector<uint8_t>& cipherData) = 0;

    // Decrypt Data
    virtual bool DecryptData(
            IKeyPair* keyPair,
            const std::vector<uint8_t>& cipherData,
            std::vector<uint8_t>& plainData) = 0;

};

}


#endif //CYBERLIB_BUILD_IENCIPHER_H
