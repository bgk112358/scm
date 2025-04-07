// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//

#include "x509_pkcs12.h"

namespace cyber {

std::unique_ptr<X509Pkcs12> X509Pkcs12::Create() {
    std::unique_ptr<X509Pkcs12> result(new X509Pkcs12);
    return result;
}

bool X509Pkcs12::GenerateStruct() {
    bool res = false;
    const char *pcName = "client";
    EVP_PKEY *pKey     = nullptr;
    X509     *x509     = nullptr;
    PKCS12   *pkcs12   = nullptr;
    STACK_OF(X509) *ca = nullptr;
    X509CertChain::ptr x509CertChain = nullptr;
    // Private Key
    if (!vPrivateKey_.empty()) {
        auto *pucInput = (unsigned char *)vPrivateKey_.data();
        auto len = (long)vPrivateKey_.size();
        const unsigned char *pp = pucInput;
        if (!d2i_AutoPrivateKey(&pKey, &pp, len)) {
            fprintf(stdout, "d2i_AutoPrivateKey fail.\n");
            goto cleanup;
        }
    }
    // Certificate Key
    if (!vCertificate_.empty()) {
        const unsigned char *p = vCertificate_.data();
        if (!d2i_X509(&x509, &p, (long)vCertificate_.size())) {
            fprintf(stdout, "d2i_X509 fail.\n");
            goto cleanup;
        }
    }
    // Certificate Chain
    x509CertChain = X509CertChain::CreateFromPemEncoded(
            sCertificateChain_);
    ca = x509CertChain->value();

    // PKCS12
    pkcs12 = PKCS12_create(sPassword_.c_str(), pcName, pKey, x509, ca, 0, 0, 0, 0, 0);
    if (pkcs12 == nullptr) {
        fprintf(stdout, "PKCS12_create fail.\n");
        goto cleanup;
    }
    pkcs12_.reset(pkcs12);
    res = true;
cleanup:
    EVP_PKEY_free(pKey);
    X509_free(x509);
    return res;
}

bool X509Pkcs12::GetDerEncode(std::vector<unsigned char> *der_encode) {
    if (pkcs12_.get() == nullptr) {
        fprintf(stdout, "PKCS12 is nullptr.\n");
        return false;
    }
    unsigned char *pucBuffer = nullptr;
    int len = i2d_PKCS12(pkcs12_.get(), &pucBuffer);
    if (der_encode) {
        der_encode->clear();
        der_encode->assign(pucBuffer, pucBuffer + len);
    }
    OPENSSL_free(pucBuffer);
    return true;
}

}