// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_IKEYPAIR_H
#define CYBERLIB_BUILD_IKEYPAIR_H

#include <string>
#include <vector>
#include <openssl/evp.h>

namespace cyber {

class IKeyPair {
public:
    virtual ~IKeyPair() {
        EVP_PKEY_free(pkey_);
        pkey_ = nullptr;
    }

    // Get Algorithm Name
    virtual std::string GetAlgorithmName() = 0;

    // Generate KeyPair
    virtual bool GenerateKeyPair(int bits, const std::string& sParams) = 0;

    // Import Raw PrivateKey
    virtual bool ImportRawPrivateKey(const std::string& sParams,
                                     std::vector<unsigned char> &vRawKey) = 0;

    // Import KeyPair
    virtual bool ImportDerPublicKey(const std::vector<unsigned char>& vDerKey) = 0;
    virtual bool ImportDerPrivateKey(const std::vector<unsigned char>& vDerKey) = 0;

    // Export KeyPair
    virtual bool ExportDerPublicKey(std::vector<unsigned char>& vDerKey) = 0;
    virtual bool ExportDerPrivateKey(std::vector<unsigned char>& vDerKey) = 0;

    // Export Key Point
    virtual EVP_PKEY *GetPrivateKey() = 0;
    virtual EVP_PKEY *GetPublicKey() = 0;

protected:
    // The RSA use actual bits
    // The Ecc256 and Ed25519 use 256 bits
    int bits_ = 0;

    // The Algorithm details
    std::string params_;

    // The Openssl EVP_PKEY
    EVP_PKEY *pkey_ = nullptr;

};

}


#endif //CYBERLIB_BUILD_IKEYPAIR_H
