// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//

#include "x509_cert_chain.h"
#include "x509_certificate.h"
#include <openssl/pem.h>
#include "x509_cert_validator.h"

namespace cyber {

X509CertChain::X509CertChain(STACK_OF(X509) *stack) : stack_(stack) { }

std::unique_ptr<X509CertChain> X509CertChain::CreateFromCertChain(
        STACK_OF(X509) *stack) {
    return stack ? std::unique_ptr<X509CertChain>(new X509CertChain(stack)) : nullptr;
}

std::unique_ptr<X509CertChain> X509CertChain::CreateFromPemEncoded(
        const std::string& pem_encoded) {
    STACK_OF(X509)* x509_sk;
    X509* cert;
    BIO* bio_in;
    Openssl_error_clear();
    const auto *start =
            reinterpret_cast<const unsigned char *>(pem_encoded.data());
    if (!(bio_in = BIO_new_mem_buf(start, (int) pem_encoded.length()))) {
        LOGM_OPENSSL_ERRORS();
        return nullptr;
    }
    if (!(x509_sk = sk_X509_new_null())) {
        LOGM_OPENSSL_ERRORS();
        BIO_free_all(bio_in);
        return nullptr;
    }
    while ((cert = PEM_read_bio_X509(bio_in, nullptr, nullptr, nullptr))) {
        sk_X509_push(x509_sk, cert);
    }
    BIO_free_all(bio_in);
    return CreateFromCertChain(x509_sk);
}

std::unique_ptr<X509CertChain> X509CertChain::CreateFromDerEncoded(
        const std::string& der_encoded) {
    STACK_OF(X509)* x509_sk;
    X509* cert;
    BIO* bio_in;
    const auto *start =
            reinterpret_cast<const unsigned char *>(der_encoded.data());
    if (!(bio_in = BIO_new_mem_buf(start, (int) der_encoded.length()))) {
        LOGM_OPENSSL_ERRORS();
        return nullptr;
    }
    if (!(x509_sk = sk_X509_new_null())) {
        LOGM_OPENSSL_ERRORS();
        return nullptr;
    }
    while ((cert = d2i_X509_bio(bio_in, nullptr))) {
        sk_X509_push(x509_sk, cert);
    }
    return CreateFromCertChain(x509_sk);
}

bool X509CertChain::HasExpired() const {
    if (stack_ == nullptr) {
        return false;
    }
    int count = GetCount();
    for (int i = 0; i < count; ++i) {
        X509 *x509 = sk_X509_value(stack_, i);
        if (x509 == nullptr)
            continue;
        ASN1_TIME *notAfter = X509_getm_notAfter(x509);

        if (notAfter == nullptr)
            continue;
        if (X509_cmp_current_time(notAfter) <= 0)
            return true;
    }
    return false;
}

bool X509CertChain::CheckValidity() const {
    if (stack_ == nullptr) {
        return false;
    }
    util::Status status = VerifyCertStack(stack_);
    if (status.code() == error::Code::Ok) {
        return true;
    }
    return false;
}

int X509CertChain::GetCount() const {
    if (stack_ == nullptr) {
        return false;
    }
    return sk_X509_num(stack_);
}

bool X509CertChain::GetPemEncode(std::string & pem_encoded) {
    if (stack_ == nullptr) {
        return false;
    }
    BIO *bio;
    if (!(bio = BIO_new(BIO_s_mem()))) {
        LOGM_OPENSSL_ERRORS();
        return false;
    }
    for (int i = 0; i < GetCount(); ++i) {
        X509 *x509 = sk_X509_value(stack_, i);
        if (x509 == nullptr) {
            continue;
        }
        if (PEM_write_bio_X509(bio, x509) != 1) {
            continue;
        }
    }
    OpensslUtils::ReadBio(bio, pem_encoded);
    BIO_free(bio);
    return true;
}

X509CertChain::~X509CertChain() {
    if (stack_) {
        sk_X509_pop_free(stack_, X509_free);
    }
}



}

