// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_RSA_KEYPAIR_H
#define CYBERLIB_BUILD_RSA_KEYPAIR_H

#include "ikeypair.h"

namespace cyber {

class RsaKeyPair : public IKeyPair {

    // Get Algorithm
    std::string GetAlgorithmName() override;

    // Generate KeyPair
    bool GenerateKeyPair(int bits, const std::string& sParams) override;

    // Import Raw PrivateKey Rsa Unsupport this function.
    bool ImportRawPrivateKey(const std::string& sParams, std::vector<unsigned char> &vRawKey) override;

    // Import KeyPair
    bool ImportDerPublicKey(const std::vector<unsigned char>& vDerKey) override;
    bool ImportDerPrivateKey(const std::vector<unsigned char>& vDerKey) override;

    // Export KeyPair
    bool ExportDerPublicKey(std::vector<unsigned char>& vDerKey) override;
    bool ExportDerPrivateKey(std::vector<unsigned char>& vDerKey) override;

    // Export Key Point
    EVP_PKEY * GetPrivateKey() override;
    EVP_PKEY * GetPublicKey() override;

};


}

#endif //CYBERLIB_BUILD_RSA_KEYPAIR_H
