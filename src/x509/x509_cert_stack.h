// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//
#ifndef SVKD_BUILD_X509_CERT_STACK_H
#define SVKD_BUILD_X509_CERT_STACK_H

#include "util/util.h"
#include "x509_certificate.h"

namespace cyber {

class X509CertStack {

public:

    typedef std::unique_ptr<X509CertStack> ptr;

    static X509CertStack::ptr CreateFromPemString(
            const std::string& pem_string);

    static X509CertStack::ptr CreateFromBase64String(
            const std::string& base64_string);

    static X509CertStack::ptr CreateFromX509Stack(
            STACK_OF(X509) *x509_stack);

    // Add Certificate to CertStack.
    bool PushCertificate(X509Certificate *certificate);
    bool PushCertificate(const X509Certificate& certificate);

    // Get Certificate Stack
    STACK_OF(X509) *value() { return stack_; }

    // Return certificate number
    int Count();

    // Return pem encode value of certificate stack
    bool GetPEMEncode(std::string *sStr);

    // Returns der encode value of certificate stack for the specified location
    bool GetDerEncode(std::vector<unsigned char> &vDer, int idx = 0);

    // Print X509 stack
    void PrintStruct(FILE *fp = stdout);

    // Life cycle
    ~X509CertStack();

private:
    explicit X509CertStack(stack_st_X509 *x509_stack);

    STACK_OF(X509) *stack_ = nullptr;
};

}

#endif //SVKD_BUILD_X509_CERT_STACK_H
