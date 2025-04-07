// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//
#ifndef SVKD_BUILD_X509_CERT_VALIDATOR_H
#define SVKD_BUILD_X509_CERT_VALIDATOR_H

#include <string>
#include "util/status_util.h"
#include "x509_cert_stack.h"

namespace cyber {

enum class CRLPolicy {
    // Do not check CRL
    CRL_NO_CHECK,

    // Revocation is only checked if a CRL is provided.
    CRL_OPTIONAL,

    // Revocation is always checked. A missing CRL results in failure.
    CRL_REQUIRED,
};

util::Status VerifyDeviceCertUsingCustomTrustStore(
    const std::string& sTrustStore,
    const std::string& sDeviceCert,
    const std::string& sDeviceCrl,
    CRLPolicy policy);

util::Status VerifyCertStack(STACK_OF(X509) *trusted_certs);

}

#endif //SVKD_BUILD_X509_CERT_VALIDATOR_H
