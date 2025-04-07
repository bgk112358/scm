// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//
#ifndef SVKD_BUILD_X509_PKCS12_H
#define SVKD_BUILD_X509_PKCS12_H

#include <memory>
#include <string>
#include <vector>
#include <openssl/pkcs12.h>

#include "../crypto/asymmetric_key.h"
#include "x509_certificate.h"
#include "x509_cert_chain.h"

namespace cyber {

class X509Pkcs12 {
public:
    typedef std::unique_ptr<X509Pkcs12> ptr;

    static X509Pkcs12::ptr Create();

    // Set Password
    void SetPassword(const std::string& sStr) { sPassword_ = sStr; }

    // Set PrivateKey
    void SetPrivateKey(const std::vector<unsigned char>& vData) {
        vPrivateKey_ = vData;
    }

    // Set Certificate
    void SetCertificate(const std::vector<unsigned char>& vData) {
        vCertificate_ = vData;
    }

    // Set CertificateChain
    void SetCertificateChain(const std::string& sData) {
        sCertificateChain_ = sData;
    }

    // Generate Struct
    bool GenerateStruct();

    // Der coding structure
    bool GetDerEncode(std::vector<unsigned char> * der_encode);

private:
    std::string sPassword_;
    std::vector<unsigned char> vPrivateKey_;
    std::vector<unsigned char> vCertificate_;
    std::string sCertificateChain_;
    internal::UniquePtr<PKCS12> pkcs12_ = nullptr;
};

}

#endif //SVKD_BUILD_X509_PKCS12_H
