// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//

#include "cyber_saf.h"
#include "handle/handler.h"
#include "x509/x509.h"
#include "util/util.h"
#include "x509/x509_util.h"
#include "container/container.h"
#include "container/container_builder.h"
#include "container/container_resolver.h"
#include "common/common.h"
#include "util/path_utils.h"

// request pkcs#7 message_type.
// PKCSReq(19), CertRep(3), GetCertInitial(20), GetCert(21), GetCRL(22)
int message_type_ext;

using namespace cyber;

int CY_SAF_AddTrustedCaCertificate(
        void *hAppHandle,
        const unsigned char *pucCertificate,
        unsigned int uiCertificateLen)
{
    DCHECK_NUL(hAppHandle, pucCertificate);
    auto *handle = static_cast<Handler *>(hAppHandle);
    // Initialization judgment
    if (!handle->isInitialized()) {
        LOGM(ERROR,"NOT Initalized\n");
        return error::Code::NotInitializeErr;
    }
    // P7 Certificate filepath.
    int rv = CY_SAF_InternalWriteContainer(
            hAppHandle,
            nullptr,
            0,
            CERT_CHAIN,
            (unsigned char *)pucCertificate,
            uiCertificateLen);
    return rv;
}

int CY_SAF_GetTrustedCaCertificateCount(
        void *hAppHandle,
        unsigned int *puiCount) {
    DCHECK_NUL(hAppHandle, hAppHandle, puiCount);
    auto *handle = static_cast<Handler *>(hAppHandle);
    // Initialization judgment
    if (!handle->isInitialized()) {
        LOGM(ERROR,"NOT Initalized\n");
        return error::Code::NotInitializeErr;
    }
    // File Path
    char pcContainerPath[SGD_MAX_SIZE] = {0};
    int rv = CY_SAF_InternalGetContainerPath(
            hAppHandle,
            nullptr,
            0,
            CERT_CHAIN,
            pcContainerPath,
            SGD_MAX_SIZE);
    if (rv != error::Code::Ok) {
        LOGM(ERROR, "InternalGetContainerPath fail.");
        return rv;
    }
    std::vector<unsigned char> vData;
    IoUtils::ReadFile(pcContainerPath, vData);
    std::string encode(reinterpret_cast<const char *>(vData.data()), vData.size());
    std::unique_ptr<X509CertChain> x509CertChain =
            X509CertChain::CreateFromPemEncoded(encode);
    if (x509CertChain == nullptr) {
        LOGM(ERROR, "Create certificate chain fail.");
        return error::Code::CertEncodeErr;
    }
    *puiCount = x509CertChain->GetCount();
    return error::Code::Ok;
}

int CY_SAF_GetTrustedCaCertificate(
        void *hAppHandle,
        unsigned int uiIndex,
        unsigned char *pucCertificate,
        unsigned int *puiCertificateLen)
{
    DCHECK_NUL(hAppHandle);
    DCHECK_NUL(puiCertificateLen);
    int rv = 0;
    auto *handle = static_cast<Handler *>(hAppHandle);
    char cContainerPath[SGD_MAX_SIZE] = {0};
    std::vector<unsigned char> vBuffer;

    FUNC_ENTRY;
    LOG_PARAMETER(hAppHandle);

    // Initialization judgment
    if (!handle->isInitialized()) {
        LOGM(ERROR,"NOT Initalized\n");
        rv = error::Code::NotInitializeErr;
        goto cleanup;
    }

     rv = CY_SAF_InternalGetContainerPath(
            hAppHandle,
            nullptr,
            0,
            CERT_CHAIN,
            cContainerPath,
            SGD_MAX_SIZE);
    if (rv != error::Code::Ok) {
        LOGM(ERROR, "GetContainerPath fail, fail code: " << std::hex << rv);
        goto cleanup;
    }
    if (!FileUtils::IsExist(cContainerPath)) {
        LOGM(INFO, "TrustedCaCertificate not exits, filePath: " << cContainerPath);
        rv = error::Code::CertNotFoundErr;
        goto cleanup;
    }
    IoUtils::ReadFile(cContainerPath, vBuffer);
    if (pucCertificate == nullptr) {
        *puiCertificateLen = vBuffer.size();
        goto cleanup;
    }
    if (*puiCertificateLen < vBuffer.size()) {
        rv = error::Code::IndataLenErr;
        goto cleanup;
    }
    memcpy(pucCertificate, vBuffer.data(), vBuffer.size());
    *puiCertificateLen = vBuffer.size();
    rv = error::Code::Ok;
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_VerifyTrustedCaCertificate(
        void *hAppHandle,
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen)
{
    auto *handle = static_cast<Handler *>(hAppHandle);
    // Initialization judgment
    if (!handle->isInitialized()) {
        LOGM(ERROR,"NOT Initalized\n");
        return error::Code::NotInitializeErr;
    }
    std::unique_ptr<X509CertChain> cert_chain = X509CertChain::CreateFromPemEncoded(
            std::string((const char *)pucCertificate, uiCertificateLen));
    if (cert_chain == nullptr) {
        return error::Code::IndataErr;
    }
    bool res = cert_chain->HasExpired();
    if (res) {
        return error::Code::CertHasExpiredErr;
    }
    return error::Code::Ok;
}

int CY_SAF_RemoveTrustedCaCertificate(
        void *hAppHandle,
        unsigned int uiIndex)
{
    DCHECK_NUL(hAppHandle);
    int rv = error::Code::UnknownErr;
    auto *handler = static_cast<Handler *>(hAppHandle);
    char pcContainerPath[SGD_MAX_SIZE] = { 0 };
    std::string sBaseUrl;
    FUNC_ENTRY;
    // Initialization judgment
    if (!handler->isInitialized()) {
        rv = error::Code::NotInitializeErr;
        goto cleanup;
    }
    // Pem CertificateChain
    memset(pcContainerPath, 0x00, sizeof(pcContainerPath));
    rv = CY_SAF_InternalGetContainerPath(
            hAppHandle,
            (unsigned char *) sBaseUrl.c_str(),
            sBaseUrl.size(),
            CERT_CHAIN,
            pcContainerPath,
            SGD_MAX_SIZE);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    FileUtils::DeleteFile(pcContainerPath);
    rv = error::Code::Ok;
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_GenerateCertificateSigningRequest(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        SGD_NAME_INFO *pstNameInfo,
        unsigned char *pucDerCertificateRequest,
        unsigned int *puiDerCertificateRequestLen) {
    DCHECK_NUL(hAppHandle, pucContainerName, pstNameInfo, puiDerCertificateRequestLen);
    int rv = 0;
    unsigned char ucData[2048] = {0};
    unsigned int uiDataLen = 2048;
    std::vector<unsigned char> vBuffer, vPrivateKey;
    std::unique_ptr<X509Request> x509Request(new X509Request);
    unsigned int uiAlgorithm = 0;
    std::string sAlgorithm;
    auto handler = (Handler *) hAppHandle;
    FUNC_ENTRY;
    FUNC_PARAMETER(pucContainerName);
    FUNC_PARAMETER(pstNameInfo->dn_sn);
    FUNC_PARAMETER(pstNameInfo->dn_cn);
    FUNC_PARAMETER(pstNameInfo->dn_dc1);
    FUNC_PARAMETER(pstNameInfo->dn_dc2);
    FUNC_PARAMETER(pstNameInfo->dn_dc3);
    // Initialization judgment
    if (!handler->isInitialized()) {
        rv = error::Code::NotInitializeErr;
        goto cleanup;
    }
    handler->SetClientType(pstNameInfo->dn_dc2);
    // Private Key
    rv = CY_SAF_InternalExportPrivateKey(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            1,
            &uiAlgorithm,
            ucData,
            &uiDataLen);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    switch (uiAlgorithm) {
        case Container::RSA: sAlgorithm = "RSA";     break;
        case Container::SM2: sAlgorithm = "SM2";     break;
        case Container::ECC: sAlgorithm = "ECC";     break;
        case Container::BRAINPOOL_P256R1: sAlgorithm = "BRAINPOOL_P256R1"; break;
        default: sAlgorithm = "NONE"; break;
    }
    vPrivateKey.assign(ucData, ucData + uiDataLen);
    x509Request = X509RequestBuilder()
            .SetAlgorithm(sAlgorithm)
            .SetCountry(pstNameInfo->dn_c)
            .SetStateOrProvinceName(pstNameInfo->dn_s)
            .SetLocality(pstNameInfo->dn_l)
            .SetOrganization(pstNameInfo->dn_o)
            .SetOrganizationUnit(pstNameInfo->dn_ou)
            .SetSerialNumber(pstNameInfo->dn_sn)
            .SetCommonName(pstNameInfo->dn_cn)
            .SetDomainComponents1(pstNameInfo->dn_dc1)
            .SetDomainComponents2(pstNameInfo->dn_dc2)
            .SetDomainComponents3(pstNameInfo->dn_dc3)
            .SetChallengePassword(pstNameInfo->dn_challengePassword)
            .SetSubjectAltName(pstNameInfo->dn_subjectAltName)
            .SetDerPrivateKey(vPrivateKey)
            .build();
    x509Request->GetDerEncode(&vBuffer);
    if (pucDerCertificateRequest == nullptr) {
        *puiDerCertificateRequestLen = vBuffer.size();
        rv = error::Code::Ok;
        goto cleanup;
    }
    memcpy(pucDerCertificateRequest, vBuffer.data(), vBuffer.size());
    *puiDerCertificateRequestLen = vBuffer.size();
    rv = CY_SAF_ImportCertificateSigningRequest(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            pucDerCertificateRequest,
            *puiDerCertificateRequestLen);
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_CheckCertificateWithSerialNumberMatcher(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int  uiContainerNameLen,
        unsigned char *pucSerialNumber,
        unsigned int uiSerialNumberLen)
{
    DCHECK_NUL(hAppHandle, pucSerialNumber, pucContainerName);
    int rv = 0;
    unsigned char ucCertificate[4096] = {0};
    unsigned int uiCertificateLen = 4096;
    unsigned char ucInfo[128] = {0};
    unsigned int uiInfoLen = 128;
    rv = CY_SAF_ExportCertificate(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            1,
            ucCertificate,
            &uiCertificateLen);
    if (rv != error::Code::Ok) {
        return rv;
    }
    rv = CY_SAF_GetCertificateInfo(
            ucCertificate,
            uiCertificateLen,
            SGD_CERT_SERIAL,
            ucInfo,
            &uiInfoLen);
    return rv;
}


int CY_SAF_ImportCertificateSigningRequest(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int  uiContainerNameLen,
        unsigned char *pucUsrCsr,
        unsigned int  uiUsrCsrLen)
{
    DCHECK_NUL(hAppHandle, pucContainerName, pucUsrCsr);
    int rv = 0;
    std::string sContainerName;
    std::vector<unsigned char> vData;
    std::unique_ptr<Container> cContainer(new Container);
    sContainerName.assign((const char *)pucContainerName, uiContainerNameLen);
    vData.assign(pucUsrCsr, pucUsrCsr + uiUsrCsrLen);
    cContainer = ContainerBuilder()
            .SetStorageType(Container::FILE)
            .SetContainerName(sContainerName)
            .SetUsage(Container::TLS)
            .SetAlgorithm(Container::NONE)
            .SetOriginalData(vData)
            .build();
    if (cContainer == nullptr) {
        return error::Code::ObjErr;
    }
    vData = cContainer->GetContainerData();
    rv = CY_SAF_InternalWriteContainer(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            CSR,
            vData.data(),
            vData.size());
    return rv;
}

int CY_SAF_ExportCertificateSigningRequest(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int  uiContainerNameLen,
        unsigned char *pucUsrCsr,
        unsigned int  *uiUsrCsrLen)
{
    DCHECK_NUL(hAppHandle, pucContainerName, uiUsrCsrLen);
    char pcContainerPath[SGD_MAX_SIZE] = {0};
    memset(pcContainerPath, 0x00, sizeof(pcContainerPath));
    int rv = CY_SAF_InternalGetContainerPath(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            CSR,
            pcContainerPath,
            SGD_MAX_SIZE);
    if (rv != error::Code::Ok) {
        return rv;
    }
    std::vector<unsigned char> vData;
    if (!IoUtils::ReadFile(pcContainerPath, vData)) {
        return error::Code::FileErr;
    }
    ContainerResolver resolver = ContainerResolver(vData);
    rv = resolver.Resolver(vNullPin);
    if (rv != error::Code::Ok) {
        return rv;
    }
    vData = resolver.GetPlainData();
    if (pucUsrCsr == nullptr) {
        *uiUsrCsrLen = vData.size();
        return error::Code::Ok;
    }
    if (*uiUsrCsrLen < vData.size()) {
        return error::Code::IndataLenErr;
    }
    memcpy(pucUsrCsr, vData.data(), vData.size());
    *uiUsrCsrLen = vData.size();
    return error::Code::Ok;
}

int CY_SAF_GetCertificateStatus(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int   uiContainerNameLen) {
    DCHECK_NUL(hAppHandle, pucContainerName);
    unsigned char pucInData[3] = { 0x01, 0x02, 0x03 };
    unsigned int  uiInDataLen = 3;
    unsigned char pucSignature[512] = { 0 };
    unsigned int  uiSignatureLen = 512;
    unsigned char ucInfo[128] = { 0 };
    unsigned int  uiInfoLen = 128;
    unsigned char ucCertificate[4096] = {0};
    unsigned int  uiCertificateLen    = 4096;
    FUNC_ENTRY;
    FUNC_PARAMETER(pucContainerName);
    auto handle = (Handler *)hAppHandle;
    // AsymmetricalKey operation
    int rv = CY_SAF_ExportCertificate(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            1,
            ucCertificate,
            &uiCertificateLen);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    rv = CY_SAF_VerifyCertificateByCrl(
            hAppHandle,
            ucCertificate,
            uiCertificateLen,
            nullptr,
            0);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    // If the pin is empty, the private key is not verified.
    if (handle->GetContainerPin().empty()) {
        goto cleanup;
    }
    rv = CY_SAF_GetCertificateInfo(
            ucCertificate,
            uiCertificateLen,
            SGD_CERT_ALGORITHM,
            ucInfo,
            &uiInfoLen);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    // IF SM2 需要进行加解密操作，判断本地是否存在加密证书和加密密钥。并判断加密证书和加密密钥是否匹配。
    if (strstr(reinterpret_cast<char *>(ucInfo), "RSA")) {
        // Verify CertificateKeyMatcher
        rv = CY_SAF_RsaSign(
                hAppHandle,
                pucContainerName,
                uiContainerNameLen,
                SGD_SHA256,
                pucInData,
                uiInDataLen,
                pucSignature,
                &uiSignatureLen);
        if (rv != error::Code::Ok) {
            goto cleanup;
        }
        rv = CY_SAF_RsaVerifySignByCert(
                SGD_SHA256,
                ucCertificate,
                uiCertificateLen,
                pucInData,
                uiInDataLen,
                pucSignature,
                uiSignatureLen);
    } else if (
            strstr(reinterpret_cast<char *>(ucInfo), "ECC") ||
            strstr(reinterpret_cast<char *>(ucInfo), "SM2") ||
            strstr(reinterpret_cast<char *>(ucInfo), "ED25519")) {
        rv = CY_SAF_EccSign(
                hAppHandle,
                pucContainerName,
                uiContainerNameLen,
                SGD_SHA256,
                pucInData,
                uiInDataLen,
                pucSignature,
                &uiSignatureLen);
        if (rv != error::Code::Ok) {
            goto cleanup;
        }
        rv = CY_SAF_EccVerifySignByCert(
                SGD_SHA256,
                ucCertificate,
                uiCertificateLen,
                pucInData,
                uiInDataLen,
                pucSignature,
                uiSignatureLen);
    } else {
        rv = error::Code::AlgoTypeErr;
    }
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_CheckCertificateKeyMatcher(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiSignFlag) {
    DCHECK_NUL(hAppHandle, pucContainerName);
    unsigned char pucInData[3] = { 0x01, 0x02, 0x03 };
    unsigned int  uiInDataLen = 3;
    unsigned char pucSignature[512] = { 0 };
    unsigned int  uiSignatureLen = 512;
    unsigned char ucInfo[128] = { 0 };
    unsigned int  uiInfoLen = 128;
    unsigned char *pucCertificate = nullptr;
    unsigned int  uiCertificateLen = 0;
    FUNC_ENTRY;
    FUNC_PARAMETER(pucContainerName);
    FUNC_PARAMETER(uiSignFlag);
    // AsymmetricalKey operation
    int rv = CY_SAF_ExportCertificate(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiSignFlag,
            pucCertificate,
            &uiCertificateLen);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    pucCertificate = (unsigned char *)OPENSSL_malloc(uiCertificateLen);
    if (pucCertificate == nullptr) {
        rv = error::Code::MemoryErr;
        goto cleanup;
    }
    rv = CY_SAF_ExportCertificate(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiSignFlag,
            pucCertificate,
            &uiCertificateLen);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    rv = CY_SAF_VerifyCertificateByCrl(
            hAppHandle,
            pucCertificate,
            uiCertificateLen,
            nullptr,
            0);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    rv = CY_SAF_GetCertificateInfo(
            pucCertificate,
            uiCertificateLen,
            SGD_CERT_ALGORITHM,
            ucInfo,
            &uiInfoLen);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    // IF SM2 需要进行加解密操作，判断本地是否存在加密证书和加密密钥。并判断加密证书和加密密钥是否匹配。
    if (strstr(reinterpret_cast<char *>(ucInfo), "RSA")) {
        // Verify CertificateKeyMatcher
        rv = CY_SAF_RsaSign(
                hAppHandle,
                pucContainerName,
                uiContainerNameLen,
                SGD_SHA256,
                pucInData,
                uiInDataLen,
                pucSignature,
                &uiSignatureLen);
        if (rv != error::Code::Ok) {
            goto cleanup;
        }
        rv = CY_SAF_RsaVerifySignByCert(
                SGD_SHA256,
                pucCertificate,
                uiCertificateLen,
                pucInData,
                uiInDataLen,
                pucSignature,
                uiSignatureLen);
    } else if (
            strstr(reinterpret_cast<char *>(ucInfo), "ECC") ||
            strstr(reinterpret_cast<char *>(ucInfo), "SM2") ||
            strstr(reinterpret_cast<char *>(ucInfo), "ED25519")) {
        rv = CY_SAF_EccSign(
                hAppHandle,
                pucContainerName,
                uiContainerNameLen,
                SGD_SHA256,
                pucInData,
                uiInDataLen,
                pucSignature,
                &uiSignatureLen);
        if (rv != error::Code::Ok) {
            goto cleanup;
        }
        rv = CY_SAF_EccVerifySignByCert(
                SGD_SHA256,
                pucCertificate,
                uiCertificateLen,
                pucInData,
                uiInDataLen,
                pucSignature,
                uiSignatureLen);
    } else {
        rv = error::Code::AlgoTypeErr;
    }
cleanup:
    OPENSSL_free(pucCertificate);
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_CheckCertificateAvailable(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiSignFlag,
        unsigned char *pucCertificate,
        unsigned int *uiCertificateLen)
{
    DCHECK_NUL(hAppHandle, pucContainerName);
    FUNC_ENTRY;
    FUNC_PARAMETER(pucContainerName);
    FUNC_PARAMETER(uiSignFlag);
    // AsymmetricalKey operation
    int rv = CY_SAF_ExportCertificate(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiSignFlag,
            pucCertificate,
            uiCertificateLen);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    rv = CY_SAF_VerifyCertificateByCrl(
            hAppHandle,
            pucCertificate,
            *uiCertificateLen,
            nullptr,
            0);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_ImportCertificate(
        void  *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int   uiContainerNameLen,
        unsigned int   uiSignFlag,
        unsigned char *pucUsrCertificate,
        unsigned int   uiUsrCertificateLen)
{
    DCHECK_NUL(hAppHandle, pucContainerName, pucUsrCertificate);
    int rv = error::Code::UnknownErr;
    auto handle = (Handler *)hAppHandle;
    std::unique_ptr<Container> container(new Container);
    std::string sContainerName;
    std::vector<unsigned char> vData;
    unsigned int uiContainerType = SIGN_CERT;
    FUNC_ENTRY;
    FUNC_PARAMETER(pucContainerName);
    FUNC_PARAMETER(uiSignFlag);
    if (!handle->isInitialized()) {
        rv = error::Code::NotInitializeErr;
        goto cleanup;
    }
    if (uiSignFlag == 0) {
        uiContainerType = ENC_CERT;
    }
    rv = CY_SAF_VerifyCertificate(
            hAppHandle,
            pucUsrCertificate,
            uiUsrCertificateLen);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    sContainerName.assign((const char *)pucContainerName, uiContainerNameLen);
    vData.assign(pucUsrCertificate, pucUsrCertificate + uiUsrCertificateLen);
    container = ContainerBuilder()
            .SetStorageType(Container::CERTIFICATE)
            .SetContainerName(sContainerName)
            .SetUsage(Container::TLS)
            .SetAlgorithm(Container::NONE)
            .SetOriginalData(vData)
            .build();
    if (container == nullptr) {
        rv = error::Code::ObjErr;
        goto cleanup;
    }
    vData = container->GetContainerData();
    rv = CY_SAF_InternalWriteContainer(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiContainerType,
            vData.data(),
            vData.size());
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_ImportCertificateEx(
        void  *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int  uiContainerNameLen,
        unsigned int  uiSignFlag,
        unsigned char *pucAlias,
        unsigned int  uiAliasLen,
        unsigned char *pucUsrCertificate,
        unsigned int  uiUsrCertificateLen)
{
    DCHECK_NUL(hAppHandle, pucContainerName, pucUsrCertificate);
    auto handle = (Handler *)hAppHandle;
    std::string sContainerName;
    std::vector<unsigned char> vData;
    std::unique_ptr<Container> container(new Container);
    if (!handle->isInitialized()) {
        return error::Code::NotInitializeErr;
    }
    unsigned int uiContainerType = SIGN_CERT;
    if (uiSignFlag == 0) {
        uiContainerType = ENC_CERT;
    }
    int rv = CY_SAF_VerifyCertificate(
            hAppHandle,
            pucUsrCertificate,
            uiUsrCertificateLen);
    if (rv != error::Code::Ok) {
        LOGM(ERROR, "VerifyCertificate fail, fail code: " << std::hex << rv);
        return rv;
    }
    sContainerName.assign((const char *)pucAlias, uiAliasLen);
    vData.assign(pucUsrCertificate, pucUsrCertificate + uiUsrCertificateLen);
    container = ContainerBuilder()
            .SetStorageType(Container::CERTIFICATE)
            .SetContainerName(sContainerName)
            .SetUsage(Container::OTA)
            .SetAlgorithm(Container::NONE)
            .SetOriginalData(vData)
            .build();
    if (container == nullptr) {
        return error::Code::ObjErr;
    }
    vData = container->GetContainerData();
    rv = CY_SAF_InternalWriteContainer(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiContainerType,
            vData.data(),
            vData.size());
    return rv;
}


int CY_SAF_ExportCertificate(
        void  *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int  uiContainerNameLen,
        unsigned int  uiSignFlag,
        unsigned char *pucUsrCertificate,
        unsigned int  *puiUsrCertificateLen)
{
    DCHECK_NUL(hAppHandle, pucContainerName);
    int rv;
    auto handle = (Handler *)hAppHandle;
    unsigned int uiContainerType = SIGN_CERT;
    FUNC_ENTRY;
    FUNC_PARAMETER(pucContainerName);
    FUNC_PARAMETER(uiSignFlag);
    // Determine initialization
    if (!handle->isInitialized()) {
        rv = error::Code::NotInitializeErr;
        goto cleanup;
    }
    if (uiSignFlag == 0) {
        uiContainerType = ENC_CERT;
    }
    // Read Container
    rv = CY_SAF_InternalReadContainer(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiContainerType,
            nullptr,
            0,
            nullptr,
            pucUsrCertificate,
            puiUsrCertificateLen);
    if (rv == error::Code::FileNotFoundErr) {
        rv = error::Code::CertNotFoundErr;
    }
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_RemoveCertificate(
        void  *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiSignFlag)
{
    DCHECK_NUL(hAppHandle, pucContainerName);
    int rv;
    unsigned int uiContainerType;
    char pcContainerPath[SGD_MAX_SIZE] = {0};
    auto handle = (Handler *)hAppHandle;
    FUNC_ENTRY;
    FUNC_PARAMETER(pucContainerName);
    FUNC_PARAMETER(uiSignFlag);
    if (!handle->isInitialized()) {
        rv = error::Code::NotInitializeErr;
        goto cleanup;
    }
    uiContainerType = SIGN_CERT;
    if (uiSignFlag == 0) {
        uiContainerType = ENC_CERT;
    }
    rv = CY_SAF_InternalGetContainerPath(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiContainerType,
            pcContainerPath,
            SGD_MAX_SIZE);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    FUNC_PARAMETER(pcContainerPath);
    FileUtils::DeleteFile(pcContainerPath);
    rv = error::Code::Ok;
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_ExportP12Certificate(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int  uiContainerNameLen,
        const char    *pcPassword,
        unsigned char *pucCertificate,
        unsigned int  *uiCertificateLen)
{
    DCHECK_NUL(hAppHandle, pucContainerName, pcPassword, pucCertificate, uiCertificateLen);
    int rv = -1;
    unsigned int uiContainerType;
    unsigned char *pucLocalCertificate = nullptr;
    unsigned int uiLocalCertificateLen = 0;
    unsigned char *pucLocalCertificateChain = nullptr;
    unsigned int uiLocalCertificateChainLen = 0;
    unsigned char ucPrivateKey[4096] = {0};
    unsigned int  uiPrivateKeyLen    = 4096;
    char pcContainerPath[SGD_MAX_SIZE] = {0};
    auto handle = (Handler *)hAppHandle;
    FUNC_ENTRY;
    FUNC_PARAMETER(pucContainerName);
    if (!handle->isInitialized()) {
        LOGM(ERROR,"NOT Initalized\n");
        rv = error::Code::NotInitializeErr;
        goto cleanup;
    }
    // Local Sign Certificate
    rv = CY_SAF_ExportCertificate(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            1,
            pucLocalCertificate,
            &uiLocalCertificateLen);
    if (rv != error::Code::Ok) {
        return rv;
    }
    pucLocalCertificate = (unsigned char *)OPENSSL_malloc(uiLocalCertificateLen);
    if (pucCertificate == nullptr) {
        rv = error::Code::MemoryErr;
        goto cleanup;
    }
    rv = CY_SAF_ExportCertificate(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            1,
            pucLocalCertificate,
            &uiLocalCertificateLen);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    // Local Certificate Chain
    rv = CY_SAF_GetTrustedCaCertificate(
            hAppHandle,
            0,
            nullptr,
            &uiLocalCertificateChainLen);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    pucLocalCertificateChain = (unsigned char *)OPENSSL_malloc(uiLocalCertificateChainLen);
    if (pucLocalCertificateChain == nullptr) {
        rv = error::Code::MemoryErr;
        goto cleanup;
    }
    rv = CY_SAF_GetTrustedCaCertificate(
            hAppHandle,
            0,
            pucLocalCertificateChain,
            &uiLocalCertificateChainLen);
    if (rv != 0) {
        goto cleanup;
    }
    rv = CY_SAF_InternalExportPrivateKey(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            1,
            nullptr,
            ucPrivateKey,
            &uiPrivateKeyLen);
    if (rv != 0) {
        goto cleanup;
    }
    rv = CY_SAF_Pkcs12_EncodeData(
            hAppHandle,
            pucLocalCertificate,
            uiLocalCertificateLen,
            pucLocalCertificateChain,
            uiLocalCertificateChainLen,
            ucPrivateKey,
            uiPrivateKeyLen,
            pcPassword,
            pucCertificate,
            uiCertificateLen);
cleanup:
    OPENSSL_free(pucLocalCertificate);
    OPENSSL_free(pucLocalCertificateChain);
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_DownloadCrl(
        void *hAppHandle,
        const char *pcCrlUrl,
        unsigned char *pucDerCrl,
        unsigned int *uiDerCrlLen)
{
    DCHECK_NUL(hAppHandle, pcCrlUrl);
    auto handle = (Handler *)hAppHandle;
    if (!handle->isInitialized()) {
        LOGM(ERROR,"NOT Initalized\n");
        return error::Code::NotInitializeErr;
    }
    auto *pucContainerName = (unsigned char *) pcCrlUrl;
    unsigned int uiContainerNameLen = strlen(pcCrlUrl);
    char pcContainerPath[SGD_MAX_SIZE] = {0};
    unsigned int uiContainerPathLen = SGD_MAX_SIZE;
    int rv = CY_SAF_InternalGetContainerPath(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            CRL,
            pcContainerPath,
            uiContainerPathLen);
    if (rv != 0) {
        LOGM(ERROR, "GetContainerPath fail, fail code: " << std::hex << rv);
        return rv;
    }
    std::unique_ptr<X509CRL> x509Crl = X509CRL::CreateFromFile(pcContainerPath);
    if (x509Crl == nullptr || x509Crl->HasExpired()) {
        LOGM(INFO, "Download Crl, Crl Path: " <<  pcCrlUrl);
        x509Crl = X509CRL::CreateFromUrl(pcCrlUrl);
    }
    if (x509Crl == nullptr) {
        return error::Code::UnknownErr;
    }
    std::string sEncode;
    x509Crl->GetDerEncode(&sEncode);
    if (!IoUtils::WriteFile(
            pcContainerPath,
            reinterpret_cast<const unsigned char *>(sEncode.data()), sEncode.size())) {
        LOGM(ERROR, "Write Crl fail.");
        rv = error::Code::FileErr;
        return rv;
    }
    if (pucDerCrl)   memcpy(pucDerCrl, sEncode.c_str(), sEncode.size());
    if (uiDerCrlLen) *uiDerCrlLen = sEncode.size();
    return error::Code::Ok;
}

int CY_SAF_VerifyCertificate(
        void *hAppHandle,
        unsigned char *pucUsrCertificate,
        unsigned int uiUsrCertificateLen)
{
    DCHECK_NUL(hAppHandle, pucUsrCertificate);
    FUNC_ENTRY;
    auto handle = (Handler *)hAppHandle;
    if (!handle->isInitialized()) {
        LOGM(ERROR,"NOT Initalized\n");
        return error::Code::NotInitializeErr;
    }
    std::string sTrustChain, sLeaf;
    util::Status status;
    // Certificate Chain
    unsigned int uiCertificateLen = 8192;
    auto pucCertificate = (unsigned char *)OPENSSL_zalloc(uiCertificateLen);
    int rv = CY_SAF_GetTrustedCaCertificate(
            hAppHandle,
            0,
            pucCertificate,
            &uiCertificateLen);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    sTrustChain = std::string(
            reinterpret_cast<const char *>(pucCertificate),
            uiCertificateLen);
    
    // User Certificate
    sLeaf = std::string(
            reinterpret_cast<const char*>(pucUsrCertificate),
            uiUsrCertificateLen);

    // Certificate chain verify
    status = VerifyDeviceCertUsingCustomTrustStore(
            sTrustChain,
            sLeaf,
            "",
            CRLPolicy::CRL_NO_CHECK);
    rv = status.code();
cleanup:
    OPENSSL_free(pucCertificate);
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_VerifyCertificateByCrl(
        void *hAppHandle,
        unsigned char *pucUsrCertificate,
        unsigned int uiUsrCertificateLen,
        unsigned char *pucDerCrl,
        unsigned int uiDerCrlLen)
{
    DCHECK_NUL(hAppHandle, pucUsrCertificate);
    FUNC_ENTRY;
    auto handle = (Handler *)hAppHandle;
    if (!handle->isInitialized()) {
        LOGM(ERROR,"NOT Initalized\n");
        return error::Code::NotInitializeErr;
    }
    std::string sTrustChain, sLeaf, sCrl;
    util::Status status;
    // Certificate Chain
    unsigned int uiCertificateLen = 8192;
    auto pucCertificate = (unsigned char *)OPENSSL_zalloc(uiCertificateLen);
    int rv = CY_SAF_GetTrustedCaCertificate(
            hAppHandle,
            0,
            pucCertificate,
            &uiCertificateLen);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    sTrustChain = std::string(
            reinterpret_cast<const char *>(pucCertificate),
            uiCertificateLen);

    // User Certificate
    sLeaf = std::string(
            reinterpret_cast<const char*>(pucUsrCertificate),
            uiUsrCertificateLen);

    // Crl
    if (pucDerCrl) {
        sCrl = std::string(
                reinterpret_cast<const char *>(pucDerCrl),
                uiDerCrlLen);
    } else {
        unsigned char *pucBuffer = nullptr;
        unsigned int  pucBufferLen = 0;
        unsigned char pucInfo[1024] = {0};
        unsigned int puiInfoLen = 1024;
        rv = CY_SAF_GetCertificateInfo(
                pucUsrCertificate,
                uiUsrCertificateLen,
                SGD_EXT_CRLDISTRIBUTIONPOINTS_INFO,
                pucInfo,
                &puiInfoLen);
        if (rv != error::Code::Ok) {
            LOGM(ERROR, "GetCertificateInfo Crl fail.");
        }
        rv = CY_SAF_DownloadCrl(
                hAppHandle,
                reinterpret_cast<const char *>(pucInfo),
                nullptr,
                &pucBufferLen);
        if (rv != error::Code::Ok) {
            LOGM(ERROR, "DownloadCrl fail, fail code: " + std::to_string(rv));
        } else {
            pucBuffer = (unsigned char *)OPENSSL_zalloc(pucBufferLen);
            rv = CY_SAF_DownloadCrl(
                    hAppHandle,
                    reinterpret_cast<const char *>(pucInfo),
                    pucBuffer,
                    &pucBufferLen);
            if (rv != error::Code::Ok) {
                LOGM(ERROR, "DownloadCrl fail, fail code: " + std::to_string(rv));
            }
        }
        if (pucBuffer != nullptr) {
            sCrl = std::string(
                    reinterpret_cast<const char *>(pucBuffer),
                    pucBufferLen);
        }
        OPENSSL_free(pucBuffer);
    }

    // Certificate chain verify
    status = VerifyDeviceCertUsingCustomTrustStore(
            sTrustChain,
            sLeaf,
            sCrl,
            CRLPolicy::CRL_OPTIONAL);
    rv = status.code();
cleanup:
    OPENSSL_free(pucCertificate);
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_GetCertificateStateByOCSP(
        void *hAppHandle,
        unsigned char *pcOcspHostURL,
        unsigned int uiOcspHostURLLen,
        unsigned char *pucUsrCertificate,
        unsigned int uiUsrCertificateLen,
        unsigned char *pucCACertificate,
        unsigned int uiCACertificateLen)
{
    return error::Code::NotSupportYetErr;
}

int CY_SAF_GetCertificateInfo(
        unsigned char *pucDerCertificate,
        unsigned int uiDerCertificateLen,
        unsigned int uiInfoType,
        unsigned char *pucInfo,
        unsigned int *puiInfoLen)
{
    DCHECK_NUL(pucDerCertificate, pucInfo, puiInfoLen);
    int rv = error::Code::UnknownErr;
    size_t bits = 0;
    unsigned int uiLen = 0;
    bool result = false;
    std::vector<unsigned char> vBuffer;
    std::string sBuffer;
    X509Certificate::ptr x509ptr;
    FUNC_ENTRY;
    FUNC_PARAMETER(uiInfoType);
    x509ptr = X509Certificate::CreateFromDerString(
            pucDerCertificate,
            uiDerCertificateLen);
    if (x509ptr == nullptr) {
        rv = error::Code::CertEncodeErr;
        goto cleanup;
    }
    switch (uiInfoType) {
        case SGD_CERT_VERSION:
            result = x509ptr->GetVersion(&sBuffer);
            vBuffer.assign(sBuffer.data(), sBuffer.data() + sBuffer.size());
            uiLen = sBuffer.size();
            break;
        case SGD_CERT_SERIAL:
            result = x509ptr->GetSerialNumber(&sBuffer);
            vBuffer.assign(sBuffer.data(), sBuffer.data() + sBuffer.size());
            uiLen = sBuffer.size();
            break;
        case SGD_CERT_ISSUER:
            result = x509ptr->GetIssuerName(&sBuffer);
            vBuffer.assign(sBuffer.data(), sBuffer.data() + sBuffer.size());
            uiLen = sBuffer.size();
            break;
        case SGD_CERT_VALID_TIME:
            result = x509ptr->GetExpirationTime(&sBuffer);
            vBuffer.assign(sBuffer.data(), sBuffer.data() + sBuffer.size());
            uiLen = sBuffer.size();
            break;
        case SGD_CERT_SUBJECT:
            result = x509ptr->GetSubjectName(&sBuffer);
            vBuffer.assign(sBuffer.data(), sBuffer.data() + sBuffer.size());
            uiLen = sBuffer.size();
            break;
        case SGD_CERT_DER_PUBLIC_KEY:
            result = x509ptr->GetSubjectPublicKey(&vBuffer);
            uiLen = vBuffer.size();
            break;
        case SGD_CERT_ALGORITHM:
            result = x509ptr->GetSubjectPublicKeyInfo(&bits, &sBuffer);
            uiLen = sBuffer.size();
            break;
        case SGD_EXT_AUTHORITYKEYIDENTIFIER_INFO:
            result = x509ptr->GetAuthorityKeyIdentify(&sBuffer);
            uiLen = sBuffer.size();
            break;
        case SGD_EXT_SUBJECTKEYIDENTIFIER_INFO:
            result = x509ptr->GetSubjectKeyIdentify(&sBuffer);
            uiLen = sBuffer.size();
            break;
        case SGD_EXT_KEYUSAGE_INFO:
            result = x509ptr->GetKeyUsage(&sBuffer);
            uiLen = sBuffer.size();
            break;
        case SGD_EXT_CRLDISTRIBUTIONPOINTS_INFO:
            result = x509ptr->GetCrlDistributionPoints(&sBuffer);
            uiLen = sBuffer.size();
            break;
        case SGD_SUBJECT_SERIAL_NUMBER:
            result = x509ptr->GetSubjectSerialNumber(&sBuffer);
            uiLen = sBuffer.size();
            break;
        default:
            break;
    }
    if (!result) {
        rv = error::Code::GetCertInfoErr;
        goto cleanup;
    }
    if (*puiInfoLen < uiLen) {
        rv = error::Code::IndataLenErr;
        goto cleanup;
    }
    if (!vBuffer.empty()) {
        memcpy(pucInfo, vBuffer.data(), vBuffer.size());
        *puiInfoLen = vBuffer.size();
    }
    if (!sBuffer.empty()) {
        memcpy(pucInfo, sBuffer.c_str(), sBuffer.length());
        *puiInfoLen = sBuffer.length();
    }
    rv = error::Code::Ok;
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_GetCertificateKeyUsage(
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        unsigned int *puiUsage)
{
    DCHECK_NUL(pucCertificate, puiUsage);
    X509Certificate::ptr x509ptr = X509Certificate::CreateFromDerString(
            pucCertificate,
            uiCertificateLen);
    if (x509ptr == nullptr) {
        return error::Code::CertEncodeErr;
    }
    X509Certificate::ExtendedKeyUsage keyUsage;
    x509ptr->GetExtendedKeyUsage(&keyUsage);
    *puiUsage = keyUsage;
    return error::Code::Ok;
}