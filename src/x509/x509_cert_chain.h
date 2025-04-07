// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//
#ifndef SVKD_BUILD_X509_CERT_CHAIN_H
#define SVKD_BUILD_X509_CERT_CHAIN_H

#include <string>
#include <vector>
#include "util/util.h"

namespace cyber {

class X509CertChain {
public:

    typedef std::unique_ptr<X509CertChain> ptr;

    // Create Certificate Chain
    static X509CertChain::ptr CreateFromPemEncoded(const std::string& pem_encoded);
    static X509CertChain::ptr CreateFromDerEncoded(const std::string& der_encoded);
    static X509CertChain::ptr CreateFromCertChain(stack_st_X509 *sk);

    // Property
    STACK_OF(X509) *value() { return stack_; }

    // Check whether the certificate in the certificate chain has expired
    // true is expired, otherwise no expired.
    bool HasExpired() const;

    // Check the validity of the certificate chain
    bool CheckValidity() const;

    // Number of certificates obtained.
    int GetCount() const;

    // Convert to pem format value.
    bool GetPemEncode(std::string & pem_encoded);

    ~X509CertChain();

private:
    explicit X509CertChain(stack_st_X509 *sk);
    STACK_OF(X509) *stack_;
};


}

#endif //SVKD_BUILD_X509_CERT_CHAIN_H
