// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//

#include "x509_cert_validator.h"
#include "x509_certificate.h"
#include "x509_cert_chain.h"
#include "x509_crl.h"
#include "util/log_utils.h"

namespace cyber {

// if check crl flags must in X509_V_FLAG_CRL_CHECK;
util::Status VerifyDeviceCert(
        X509 *leaf,
        STACK_OF(X509) *trusted_certs,
        STACK_OF(X509_CRL) *crls,
        unsigned long flags = 0) {
    util::Status status;
    X509_STORE_CTX *ctx = nullptr;
    X509_STORE *store = nullptr;
    int code;
    std::string message;
    if (trusted_certs == nullptr) {
        status = util::Status(error::Code::IndataErr, "trusted_certs is nullptr.");
        goto cleanup;
    }
    if (!(ctx = X509_STORE_CTX_new()) ||
        !(store = X509_STORE_new())) {
        status = util::Status(error::Code::MemoryErr, "Memory error.");
        goto cleanup;
    }
    // Crl Check flags.
    if (flags != 0) {
        X509_STORE_set_flags(store, flags);
    }
    if (flags == 0 && crls) {
        X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    }
    if (flags == 0 && crls == nullptr) {
        X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK_ALL);
    }
    // Set Check Certificate
    if (!X509_STORE_CTX_init(ctx, store, leaf, nullptr)) {
        status = util::FailStatus();
        goto cleanup;
    }
    X509_STORE_CTX_set0_trusted_stack(ctx, trusted_certs);
    if (crls) {
        X509_STORE_CTX_set0_crls(ctx, crls);
    }
    // Check Certificate
    if (X509_verify_cert(ctx) <= 0) {
        code = X509_STORE_CTX_get_error(ctx);
        message = "X509 vfy error, error code: "
                  + std::to_string(code) + " "
                  + "error string: "
                  + X509_verify_cert_error_string(code);
        int err_code = error::Code::CertVerifyErr;
        switch (code) {
            case X509_V_ERR_CERT_REVOKED:
                err_code = error::Code::CertRevokedErr;
                break;
            case X509_V_ERR_CERT_HAS_EXPIRED:
                err_code = error::Code::CertHasExpiredErr;
                break;
            case X509_V_ERR_CERT_NOT_YET_VALID:
                // The time will not be correct when tbox restarts
                err_code = error::Code::Ok;
                break;
            case X509_V_ERR_CRL_NOT_YET_VALID:
                err_code = error::Code::Ok;//2024.11.27  MCHENG crl time is not valid;
            default:
                break;
        }
        status = util::Status(err_code, message);
        goto cleanup;
    }
    status = util::OkStatus();
cleanup:
    if (status.code() != error::Code::Ok) {
        LOGM(ERROR, status.message());
    }
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return status;
}

util::Status VerifyDeviceCertUsingCustomTrustStore(
        const std::string& sTrustStore,
        const std::string& sDeviceCert,
        const std::string& sDeviceCrl,
        CRLPolicy policy)
{
    util::Status status;
    STACK_OF(X509_CRL) *crls = nullptr;
    std::unique_ptr<X509CRL> x509Crl;
    if (sTrustStore.empty() || sDeviceCert.empty()) {
        status = util::Status(error::Code::IndataErr, "Argument error.");
        return status;
    }
    std::unique_ptr<X509Certificate> x509Leaf = X509Certificate::CreateFromBytes(
            sDeviceCert);
    if (x509Leaf == nullptr) {
        status = util::Status(error::Code::IndataErr, "Leaf Cert error.");
        return status;
    }
    if (policy == CRLPolicy::CRL_NO_CHECK) {
        crls = nullptr;
    } else if (policy == CRLPolicy::CRL_OPTIONAL) {
        x509Crl = X509CRL::CreateFromDerString(sDeviceCrl);
        if (x509Crl && !x509Crl->HasExpired()) {
            crls = x509Crl->value();
        }
    } else if (policy == CRLPolicy::CRL_REQUIRED) {
        if (sDeviceCrl.empty()) {
            status = util::Status(error::Code::IndataErr, "Get crl fail.");
            return status;
        }
        x509Crl = X509CRL::CreateFromDerString(sDeviceCrl);
        if (x509Crl && !x509Crl->HasExpired()) {
            crls = x509Crl->value();
        }
    }
    std::unique_ptr<X509CertChain> x509CertChain = X509CertChain::CreateFromPemEncoded(
            sTrustStore);
    if (x509CertChain == nullptr) {
        status = util::Status(error::Code::IndataErr, "Create Cert Chain fail.");
        return status;
    }
    status = VerifyDeviceCert(
            x509Leaf->value(),
            x509CertChain->value(),
            crls,
            0);
    return status;
}

util::Status VerifyCertStack(STACK_OF(X509) *trusted_certs) {
    return VerifyDeviceCert(nullptr, trusted_certs, nullptr, 0);
}

}