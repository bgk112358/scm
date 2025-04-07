// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//

#include "x509_cert_stack.h"
#include "openssl/pem.h"
#include "crypto/base64.h"

namespace cyber {

X509CertStack::X509CertStack(struct stack_st_X509 *x509_stack) : stack_(x509_stack) { }

std::unique_ptr<X509CertStack>
X509CertStack::CreateFromX509Stack(struct stack_st_X509 *x509_stack) {
    return x509_stack ? std::unique_ptr<X509CertStack>(new X509CertStack(x509_stack)) : nullptr;
}

std::unique_ptr<X509CertStack> X509CertStack::CreateFromPemString(
        const std::string& pem_string) {
    internal::UniquePtr<BIO> bio;
    bio.reset(BIO_new_mem_buf(pem_string.data(), (int)pem_string.length()));
    if (bio == nullptr || bio.get() == nullptr) {
        LOGM_OPENSSL_ERRORS();
        return nullptr;
    }
    STACK_OF(X509) *stack;
    if (!(stack = sk_X509_new_null())) {
        LOGM_OPENSSL_ERRORS();
        return nullptr;
    }
    X509 *cert;
    while ((cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr))) {
        sk_X509_push(stack, cert);
    }
    return CreateFromX509Stack(stack);
}

std::unique_ptr<X509CertStack> X509CertStack::CreateFromBase64String(
        const std::string &base64_string) {
    internal::UniquePtr<BIO> bio;
    std::vector<unsigned char> bytes = Base64Decode(base64_string);
    bio.reset(BIO_new_mem_buf(bytes.data(), (int)bytes.size()));
    if (bio == nullptr || bio.get() == nullptr) {
        LOGM_OPENSSL_ERRORS();
        return nullptr;
    }
    STACK_OF(X509) *stack;
    if (!(stack = sk_X509_new_null())) {
        LOGM_OPENSSL_ERRORS();
        return nullptr;
    }
    X509 *cert;
    while ((cert = d2i_X509_bio(bio.get(), nullptr))) {
        sk_X509_push(stack, cert);
    }
    return CreateFromX509Stack(stack);
}

bool X509CertStack::PushCertificate(X509Certificate *certificate) {
    if (certificate == nullptr || stack_ == nullptr) {
        return false;
    }
    if (sk_X509_push(stack_, certificate->value()) > 0) {
        return false;
    }
    return true;
}

bool X509CertStack::PushCertificate(const X509Certificate& certificate) {
    if (stack_ == nullptr) {
        return false;
    }
    if (sk_X509_push(stack_, certificate.value()) > 0) {
        return false;
    }
    return true;
}

int X509CertStack::Count() {
    if (stack_ == nullptr) return 0;
    return sk_X509_num(stack_);
}

bool X509CertStack::GetPEMEncode(std::string *sStr) {
    std::string sBuffer;
    BIO *pBio;
    if (sStr == nullptr || stack_ == nullptr) {
        return false;
    }
    sStr->clear();
    if (!(pBio = BIO_new(BIO_s_mem()))) {
        return false;
    }
    for (int i = 0; i < sk_X509_num(stack_); i++) {
        X509 *x509 = sk_X509_value(stack_, i);
        if (x509 == nullptr) {
            continue;
        }
        if (PEM_write_bio_X509(pBio, x509) != 1) {
            continue;
        }
        OpensslUtils::ReadBio(pBio, sBuffer);
        BIO_reset(pBio);
        sStr->append(sBuffer);
    }
    BIO_free(pBio);
    return true;
}

bool X509CertStack::GetDerEncode(std::vector<unsigned char> &vDer, int idx) {
    bool res = false;
    std::string sBuffer;
    X509 *x509 = nullptr;
    BIO *pBio  = nullptr;
    if (stack_ == nullptr) {
        return false;
    }
    vDer.clear();
    if (!(pBio = BIO_new(BIO_s_mem()))) {
        return false;
    }
    if (idx > sk_X509_num(stack_)) {
        goto cleanup;
    }
    x509 = sk_X509_value(stack_, idx);
    if (x509 == nullptr) {
        goto cleanup;
    }
    if (i2d_X509_bio(pBio, x509) != 1) {
        goto cleanup;
    }
    OpensslUtils::ReadBio(pBio, sBuffer);
    vDer.assign(sBuffer.data(), sBuffer.data() + sBuffer.size());
    res = true;
cleanup:
    BIO_free(pBio);
    return res;
}

void X509CertStack::PrintStruct(FILE *fp) {
    if (stack_ == nullptr) return;
    for (int i = 0; i < Count(); ++i) {
        X509 *x509 = sk_X509_value(stack_, i);
        X509_print_fp(fp, x509);
    }
}

X509CertStack::~X509CertStack() {
    if (stack_) {
        sk_X509_pop_free(stack_, X509_free);
        stack_ = nullptr;
    }
}




}

