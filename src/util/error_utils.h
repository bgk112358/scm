// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluating Co., Ltd.
//
#ifndef CYBERLIB_BUILD_ERROR_UTILS_H
#define CYBERLIB_BUILD_ERROR_UTILS_H

#include <openssl/err.h>
#include "plog/Log.h"
#include "status_util.h"
#include "openssl_utils.h"

using namespace cyber::error;

[[maybe_unused]] static std::string Cyber_get_error_message(int err) {
    std::string sMessage;
    switch (err) {
        case Code::Ok:               sMessage = "Success.";       break;
        case Code::UnknownErr:       sMessage = "Unknown Error."; break;
        case Code::NotSupportYetErr: sMessage = "Unsupported Service."; break;
        case Code::FileErr:          sMessage = "File operation error."; break;
        case Code::ProviderTypeErr:  sMessage = "Service provider parameter type error."; break;
        case Code::LoadProviderErr:  sMessage = "Failed to load service provider interface."; break;
        case Code::LoadDevMngApiErr: sMessage = "Failed to load device management interface."; break;
        case Code::AlgoTypeErr:      sMessage = "Algorithm type error."; break;
        case Code::NameLenErr:       sMessage = "Name length error."; break;
        case Code::KeyUsageErr:      sMessage = "Key usage error.";   break;
        case Code::ModulusLenErr:    sMessage = "Modulus length error."; break;
        case Code::NotInitializeErr: sMessage = "Not initialized."; break;
        case Code::ObjErr:           sMessage = "Object error."; break;
        case Code::FileNotFoundErr:  sMessage = "File not found."; break;
        case Code::MemoryErr:        sMessage = "Memory error."; break;
        case Code::TimeoutErr:       sMessage = "Timeout occurred."; break;
        case Code::ConnectErr:       sMessage = "Connection failed."; break;
        case Code::ResolveHostErr:   sMessage = "Host name resolution failed."; break;
        case Code::IndataLenErr:     sMessage = "Input data length error."; break;
        case Code::IndataErr:        sMessage = "Input data error."; break;
        case Code::GenRandErr:       sMessage = "Failed to generate random number."; break;
        case Code::HashObjErr:       sMessage = "HASH object error."; break;
        case Code::HashErr:          sMessage = "HASH operation error."; break;
        case Code::GenKeyErr:        sMessage = "Failed to generate key pair."; break;
        case Code::RsaModulusLenErr: sMessage = "RSA key modulus length error."; break;
        case Code::EncErr:           sMessage = "Encryption error."; break;
        case Code::DecErr:           sMessage = "Decryption error."; break;
        case Code::HashNotEqualErr:  sMessage = "HASH values do not match."; break;
        case Code::KeyNotFoundErr:   sMessage = "Key not found."; break;
        case Code::CertNotFoundErr:  sMessage = "Certificate not found."; break;
        case Code::NotExportErr:     sMessage = "Object not exported."; break;
        case Code::CertRevokedErr:   sMessage = "Certificate revoked."; break;
        case Code::CertNotYetValidErr:  sMessage = "Certificate not yet valid."; break;
        case Code::CertHasExpiredErr:sMessage = "Certificate has expired."; break;
        case Code::CertVerifyErr:    sMessage = "Certificate verification error."; break;
        case Code::CertEncodeErr:    sMessage = "Certificate encoding error."; break;
        case Code::GenCertErr:       sMessage = "Failed to generate certificate."; break;
        case Code::GetCertInfoErr:   sMessage = "Failed to get certificate information."; break;
        case Code::CertPublicKeyNotMatchErr: sMessage = "Certificate public key does not match."; break;
        case Code::DecryptPadErr:    sMessage = "Decryption padding error."; break;
        case Code::MacLenErr:        sMessage = "MAC length error."; break;
        case Code::KeyInfoTypeErr:   sMessage = "Key type error."; break;
        case Code::NotLogin:         sMessage = "Not logged in."; break;
        case Code::KeyErr:           sMessage = "Key error."; break;
        case Code::KeyEncodeErr:     sMessage = "Key encoding error."; break;
        case Code::SignErr:          sMessage = "Signing error."; break;
        case Code::VerifyErr:        sMessage = "Verification error."; break;
        case Code::Pkcs7EncodeErr:   sMessage = "PKCS#7 encoding error."; break;
        case Code::ScepStatusErr:    sMessage = "SCEP status error."; break;
        case Code::AttributesVerifyErr: sMessage = "Attributes verification error."; break;
        case Code::MessageVerifyErr: sMessage = "Message verification error."; break;
        default:    sMessage = "Unknown Error Code.";
    }
    return sMessage;
}

[[maybe_unused]] static int Cyber_error(int err) {
    std::string sMsg = Cyber_get_error_message(err);
    LOGE << "Cyber error: " << sMsg;
    return err;
}

[[maybe_unused]] static void Cyber_error_message(const char *pcMsg) {
    LOGE << "Cyber error: " << pcMsg;
}

#endif //CYBERLIB_BUILD_ERROR_UTILS_H
