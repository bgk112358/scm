// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "x509_util.h"

#include "util/openssl_utils.h"
#include <openssl/asn1.h>
#include <openssl/x509.h>

using namespace cyber;


bool X509Utils::CreateSelfSignCert(EVP_PKEY *pkey,
                                   DigestAlgorithm digestAlgorithm,
                                   std::string *psCertificate) {
    (void)digestAlgorithm;
    bool res = false;
    X509 *x509;
    X509_NAME *subj_name;
    const EVP_MD *md = EVP_sha256();
    unsigned char *buffer = nullptr;
    int buffer_len;
    if (pkey == nullptr || psCertificate == nullptr) {
        return false;
    }
    if (!(x509 = X509_new())) {
        LOGM_OPENSSL_ERRORS();
        goto cleanup;
    }
    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), kSerialNumber);

    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), kTimeSecondsPerYear);

    if (X509_set_pubkey(x509, pkey) != 1) {
        fprintf(stderr, "x509_set_pubkey fail.");
    }
    subj_name = X509_get_subject_name(x509);
    if (subj_name) {
        X509_NAME_add_entry_by_txt(subj_name, "CN", MBSTRING_ASC,
                                   (unsigned char*)"self-sign", -1, -1, 0);
        X509_set_issuer_name(x509, subj_name);
    }
    buffer_len = X509_sign(x509, pkey, md);
    if (buffer_len <= 0) {
        fprintf(stderr, "X509_sign fail. %s", OpensslUtils::GetErrMsg().c_str());
    }
    buffer_len = i2d_X509(x509, &buffer);
    psCertificate->assign(reinterpret_cast<const char *>(buffer), buffer_len);
    res = true;
cleanup:
    X509_free(x509);
    OPENSSL_free(buffer);
    return res;
}