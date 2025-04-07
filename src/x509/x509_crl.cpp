// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//

#include "x509_crl.h"
#include "util/log_utils.h"
#include <openssl/pem.h>

namespace cyber {

X509CRL::~X509CRL() {
    if (crls_ == nullptr) return;
    sk_X509_CRL_pop_free(crls_, X509_CRL_free);
}

std::unique_ptr<X509CRL>
X509CRL::CreateFromPemString(const std::string & sPem) {
    std::unique_ptr<X509CRL> result(new X509CRL);
    BIO *bio_in;
    X509_CRL *crl;
    if (!(bio_in = BIO_new_mem_buf(sPem.data(), (int)sPem.length()))) {
        LOGM_OPENSSL_ERRORS();
        return nullptr;
    }
    if (!(crl = PEM_read_bio_X509_CRL(bio_in, nullptr, nullptr, nullptr))) {
        LOGM_OPENSSL_ERRORS();
        return nullptr;
    }
    result->crls_ = sk_X509_CRL_new_null();
    sk_X509_CRL_push(result->crls_, crl);
    return result;
}

std::unique_ptr<X509CRL>
X509CRL::CreateFromDerString(const std::string & sDer) {
    std::unique_ptr<X509CRL> result(new X509CRL);
    BIO *bio_in;
    X509_CRL *crl;
    if (!(bio_in = BIO_new_mem_buf(sDer.data(), (int)sDer.length()))) {
        return nullptr;
    }
    if (!(crl = d2i_X509_CRL_bio(bio_in, nullptr))) {
        BIO_free(bio_in);
        return nullptr;
    }
    result->crls_ = sk_X509_CRL_new_null();
    sk_X509_CRL_push(result->crls_, crl);
    BIO_free(bio_in);
    return result;
}

std::unique_ptr<X509CRL>
X509CRL::CreateFromFile(const std::string &sFileName) {
    std::unique_ptr<X509CRL> result(new X509CRL);
    X509_CRL *crl;
    BIO *bio_in;
    if (!(bio_in = BIO_new(BIO_s_file()))) {
        return nullptr;
    }
    BIO_read_filename(bio_in, sFileName.c_str());
    if (!(crl = d2i_X509_CRL_bio(bio_in, nullptr))) {
        BIO_free(bio_in);
        return nullptr;
    }
    result->crls_ = sk_X509_CRL_new_null();
    sk_X509_CRL_push(result->crls_, crl);
    BIO_free(bio_in);
    return result;
}

std::unique_ptr<X509CRL> X509CRL::CreateFromUrl(
        const std::string &sCrlUrl) {
    std::unique_ptr<X509CRL> result(new X509CRL);
//    HttpHandle httpHandle = HttpHandle(sCrlUrl);
//    util::Status status = httpHandle.GetRequest("", 10);
//    if (status.code() != error::Code::Ok) {
//        LOGM(ERROR, status.message());
//        return nullptr;
//    }
//    HttpResponse response = httpHandle.GetResponse();
//    std::string sBody = response.GetHttpBody();
//    auto *in = (const unsigned char *)sBody.c_str();
//    X509_CRL *crl = d2i_X509_CRL(nullptr, &in, (long)sBody.size());
//    if (crl == nullptr) {
//        return nullptr;
//    }
//    result->crls_ = sk_X509_CRL_new_null();
//    sk_X509_CRL_push(result->crls_, crl);
    return result;
}

bool X509CRL::GetVersion(std::string *sVersion) {
    X509_CRL *crl;
    if (crls_ == nullptr || sVersion == nullptr) {
        return false;
    }
    if (!(crl = sk_X509_CRL_value(crls_, 0))) {
        return false;
    }
    long val = X509_CRL_get_version(crl);
    *sVersion = std::to_string(val);
    return true;
}

bool X509CRL::GetIssuerName(std::string *sIssuer) {
    X509_NAME *name;
    X509_CRL *crl;
    char *str;
    if (crls_ == nullptr || sIssuer == nullptr) {
        return false;
    }
    if (!(crl = sk_X509_CRL_value(crls_, 0))) {
        return false;
    }
    if (!(name = X509_CRL_get_issuer(crl))) {
        return false;
    }
    if (!(str = X509_NAME_oneline(name, nullptr, 0))) {
        return false;
    }
    sIssuer->assign(str, strlen(str));
    OPENSSL_free(str);
    return true;
}

bool X509CRL::HasExpired() const {
    if (crls_ == nullptr) return false;
    int num = sk_X509_CRL_num(crls_);
    for (int i = 0; i < num; ++i) {
        X509_CRL *crl = sk_X509_CRL_value(crls_, i);
        if (crl == nullptr) continue;
        const ASN1_TIME *nextUpdate = X509_CRL_get0_nextUpdate(crl);
        if (nextUpdate == nullptr) {
            // If there is no next update time, it is considered expired.
            LOGM(INFO, "The next update for the CRL is unspecified.");
            return true;
        }
        int rv = X509_cmp_current_time(nextUpdate);
        if (rv <= 0) {
            LOGM(INFO, "The CRL has expired.");
            return true;
        }
    }
    return false;
}

bool X509CRL::GetPemEncode(std::string *sStr) const {
    int num;
    BIO *bio;
    if (crls_ == nullptr || sStr == nullptr) return false;
    if (!(bio = BIO_new(BIO_s_mem()))) {
        return false;
    }
    num = sk_X509_CRL_num(crls_);
    sStr->clear();
    for (int i = 0; i < num; ++i) {
        X509_CRL *crl = sk_X509_CRL_value(crls_, i);
        if (crl == nullptr) continue;
        if (PEM_write_bio_X509_CRL(bio, crl) != 1) continue;
        std::string crl_str;
        OpensslUtils::ReadBio(bio, crl_str);
        sStr->append(crl_str);
        BIO_reset(bio);
    }
    BIO_free(bio);
    return true;
}

bool X509CRL::GetDerEncode(std::string* sStr) const {
    int num;
    if (crls_ == nullptr || sStr == nullptr) return false;
    num = sk_X509_CRL_num(crls_);
    sStr->clear();
    for (int i = 0; i < num; ++i) {
        X509_CRL *crl = sk_X509_CRL_value(crls_, i);
        if (crl == nullptr) continue;
        unsigned char *buffer = nullptr;
        int len = i2d_X509_CRL(crl, &buffer);
        if (len > 0 && buffer != nullptr) {
            sStr->append(reinterpret_cast<const char *>(buffer), len);
        }
        OPENSSL_free(buffer);
    }
    return true;
}

void X509CRL::Print() {
    if (!crls_) return;
    int num = sk_X509_CRL_num(crls_);
    for (int i = 0; i < num; ++i) {
        X509_CRL *crl = sk_X509_CRL_value(crls_, i);
        if (crl) X509_CRL_print_fp(stdout, crl);
    }
}



}
