// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//
#ifndef SVKD_BUILD_X509_CRL_H
#define SVKD_BUILD_X509_CRL_H

#include <memory>
#include <openssl/x509.h>
#include "x509_cert_chain.h"

// Incremental CRL is not supported. If it is an incremental CRL,
// you need to change it

namespace cyber {

class X509CRL {
public:
    // Create an X509CRL from the PEM-encode.
    // Returns NULL on failure.
    static std::unique_ptr<X509CRL> CreateFromPemString(
            const std::string & sPem);

    // Create an X509CRL from the DER-encode.
    // Returns NULL on failure.
    static std::unique_ptr<X509CRL> CreateFromDerString(
            const std::string & sDer);

    // Create an X509CRL from the file.
    // Returns NULL on failure.
    static std::unique_ptr<X509CRL> CreateFromFile(
            const std::string& sFileName);

    // Create an X509CRL from the url, single crl download.
    // Returns NULL on failure.
    static std::unique_ptr<X509CRL> CreateFromUrl(
            const std::string& sCrlUrl);

    // Construction method.
    explicit X509CRL() = default;
    ~X509CRL();

    // Properties.
    STACK_OF(X509_CRL) *value() { return crls_; }

    // Parses and obtains the certificate crl content
    // The latest version is v2, and the default value is v2.
    bool GetVersion(std::string *version);

    // Contains the identity of the CRL issuer
    bool GetIssuerName(std::string *issuer);

    // To check the Crl next update time, the system time must be correct.
    // return true means you need to update the crl.
    bool HasExpired() const;

    // Returns the PEM encoded data from sk_X509_CRL.
    bool GetPemEncode(std::string* pem_encoded) const;

    // Returns the DER encoded data from sk_X509_CRL.
    bool GetDerEncode(std::string* der_encoded) const;

    // Output the crl structure to the terminal.
    void Print();

private:
    STACK_OF(X509_CRL) *crls_ = nullptr;
};




}


#endif //SVKD_BUILD_X509_CRL_H
