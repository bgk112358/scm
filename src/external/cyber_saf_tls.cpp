// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "cyber_saf_tls.h"
#include "cyber_saf.h"
#include "util/util.h"
#include "handle/handler.h"
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include "crypto/asymmetric_key.h"
#include "util/path_utils.h"
#include "x509/x509_certificate.h"
#include "cyber_engine.h"

using namespace cyber;

static constexpr auto engine_id = "cyber_security";

int CY_SAF_GetSSLContext(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        void ** ctx) {
    DCHECK_NUL(hAppHandle, pucContainerName);
    int rv = 0;
    char pcContainerPath[SGD_MAX_SIZE] = {0};
    unsigned char pucData[2048] = {0};
    unsigned int uiCertificateLen = 8192, uiDataLen = 2048, uiAlgorithm = 0;
    unsigned char *pucCertificate = nullptr;
    std::shared_ptr<IKeyPair> signKeyPair;
    std::shared_ptr<IKeyPair> encKeyPair;
    std::vector<unsigned char> vPrivateKey;
    ENGINE *pEngine = nullptr;
    EVP_PKEY *pkey  = nullptr;
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    FUNC_ENTRY;
    FUNC_PARAMETER(pucContainerName);
    auto *handle = static_cast<Handler *>(hAppHandle);
    // Initialized
    if (!handle->isInitialized()) {
        LOGM(ERROR,"NOT Initalized\n");
        return error::Code::NotInitializeErr;
    }
    SSL_CTX *context = SSL_CTX_new(NTLS_client_method());
    if (context == nullptr) {
        rv = error::Code::MemoryErr;
        goto cleanup;
    }
    SSL_CTX_enable_ntls(context);

    rv = CY_SAF_InternalGetContainerPath(
            hAppHandle,
            nullptr,
            0,
            CERT_CHAIN,
            pcContainerPath,
            SGD_MAX_SIZE);
    if (rv != CYBER_R_SUCCESS) {
        LOGM(ERROR, "InternalGetContainerPath fail, fail code:" + std::to_string(rv));
        goto cleanup;
    }
    uiCertificateLen = 8192;
    pucCertificate = (unsigned char *)OPENSSL_zalloc(uiCertificateLen);
    if (pucCertificate == nullptr) {
        rv = error::Code::MemoryErr;
        goto cleanup;
    }
    rv = CY_SAF_GetTrustedCaCertificate(
            hAppHandle,
            0,
            pucCertificate,
            &uiCertificateLen);
    if (rv != error::Code::Ok) {
        LOGM(ERROR, "GetTrustedCaCertificate fail, fail code:" + std::to_string(rv));
        goto cleanup;
    }
    IoUtils::WriteFile(pcContainerPath, pucCertificate, uiCertificateLen);
    rv = SSL_CTX_load_verify_locations(context, pcContainerPath, nullptr);
    if (rv != 1) {
        LOGM(ERROR, "SSL_CTX_load_verify_locations fail, fail code:" + std::to_string(rv));
        rv = error::Code::UnknownErr;
        goto cleanup;
    }
    // Sign Certificate
    uiCertificateLen = 8192;
    rv = CY_SAF_ExportCertificate(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            1,
            pucCertificate,
            &uiCertificateLen);
    if (rv != error::Code::Ok) {
        LOGM(ERROR, "ExportCertificate fail, fail code:" + std::to_string(rv));
        goto cleanup;
    }
    {
        std::string sCert = std::string(
                reinterpret_cast<const char*>(pucCertificate),
                uiCertificateLen);
        std::unique_ptr<X509Certificate> x509Certificate = X509Certificate::CreateFromBytes(sCert);
        rv = SSL_CTX_use_certificate(context, x509Certificate->value());
        if (rv != 1) {
            LOGM(ERROR, "SSL_CTX_use_sign_certificate fail, fail code:" + std::to_string(rv));
            ERR_print_errors_fp(stdout);
            rv = error::Code::CertEncodeErr;
            goto cleanup;
        }
    }
    // Enc Certificate
    uiCertificateLen = 8192;
    rv = CY_SAF_ExportCertificate(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            0,
            pucCertificate,
            &uiCertificateLen);
    if (rv == error::Code::Ok) {
        uiCertificateLen = 8192;
        std::string sCert = std::string(
                reinterpret_cast<const char*>(pucCertificate),
                uiCertificateLen);
        std::unique_ptr<X509Certificate> x509Certificate = X509Certificate::CreateFromBytes(sCert);
        rv = SSL_CTX_use_enc_certificate(context, x509Certificate->value());
        if (rv != 1) {
            LOGM(ERROR, "SSL_CTX_use_enc_certificate fail, fail code:" + std::to_string(rv));
            rv = error::Code::CertEncodeErr;
            goto cleanup;
        }
    }
    // Sign PrivateKey
    rv = CY_SAF_InternalExportPrivateKey(
            handle,
            pucContainerName,
            uiContainerNameLen,
            1,
            &uiAlgorithm,
            pucData,
            &uiDataLen);
    if (rv != error::Code::Ok) {
        LOGM(ERROR, "ExportPrivateKey fail, fail code:" + std::to_string(rv));
        goto cleanup;
    }
    // Just for get EVP_PKEY, never mind the algorithm.
    signKeyPair = AsymmetricKey::CreateKeyPair("SM2");
    if (signKeyPair == nullptr) {
        LOGM(ERROR, "Unsupport Algorithm:" << std::hex << uiAlgorithm);
        goto cleanup;
    }
    vPrivateKey.assign(pucData, pucData + uiDataLen);
    if (!signKeyPair->ImportDerPrivateKey(vPrivateKey) &&
        !signKeyPair->ImportDerPublicKey(vPrivateKey)) {
        LOGM(ERROR, "ImportDerKey fail.");
        rv = error::Code::KeyEncodeErr;
        goto cleanup;
    }
    pkey = signKeyPair->GetPrivateKey();
    if (pkey == nullptr) {
        LOGM(ERROR, "KeyPair Get pkey fail");
        rv = error::Code::KeyNotFoundErr;
        goto cleanup;
    }
    if (handle->isHardWare()) {
        pEngine =  ENGINE_by_id(engine_id);
        if (EVP_PKEY_is_sm2(pkey)) {
            EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
        }
        EVP_PKEY_set1_engine(pkey, nullptr);
    }
    rv = SSL_CTX_use_sign_PrivateKey(context, pkey);
    if (rv != 1) {
        LOGM(ERROR, "SSL_CTX_use_PrivateKey fail.");
        rv = error::Code::UnknownErr;
        goto cleanup;
    }

    // Enc PrivateKey
    rv = CY_SAF_InternalExportPrivateKey(
            handle,
            pucContainerName,
            uiContainerNameLen,
            0,
            &uiAlgorithm,
            pucData,
            &uiDataLen);
    if (rv == error::Code::Ok) {
        // Just for get EVP_PKEY, never mind the algorithm.
        encKeyPair = AsymmetricKey::CreateKeyPair("SM2");
        if (encKeyPair == nullptr) {
            LOGM(ERROR, "Unsupport Algorithm:" << std::hex << uiAlgorithm);
            goto cleanup;
        }
        vPrivateKey.assign(pucData, pucData + uiDataLen);
        if (!encKeyPair->ImportDerPrivateKey(vPrivateKey) &&
            !encKeyPair->ImportDerPublicKey(vPrivateKey)) {
            LOGM(ERROR, "ImportDerKey fail.");
            rv = error::Code::KeyEncodeErr;
            goto cleanup;
        }
        pkey = encKeyPair->GetPrivateKey();
        if (pkey == nullptr) {
            LOGM(ERROR, "KeyPair Get pkey fail");
            rv = error::Code::KeyNotFoundErr;
            goto cleanup;
        }
        rv = SSL_CTX_use_enc_PrivateKey(context, pkey);
        if (rv != 1) {
            LOGM(ERROR, "SSL_CTX_use_PrivateKey fail.");
            rv = error::Code::UnknownErr;
            goto cleanup;
        }
    }
    *ctx = context;
    rv = error::Code::Ok;
cleanup:
    if (rv != error::Code::Ok) {
        SSL_CTX_free(context);
        *ctx = nullptr;
    }
    ENGINE_free(pEngine);
    OPENSSL_free(pucCertificate);
    FUNC_EXIT_RV(rv);
    return rv;
}