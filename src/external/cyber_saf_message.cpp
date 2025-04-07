// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//

#include "cyber_saf.h"
#include "util/util.h"
#include "crypto/crypto.h"
#include "x509/x509_pkcs12.h"
#include "handle/handler.h"
#include "common/common.h"

using namespace cyber;

extern int message_type_ext;

// Internal Method
static int CY_SAF_GetHashAlgorithm(const std::string & algorithm) {
    if (algorithm.find("SHA1")) {
        return SGD_SHA1;
    } else if (algorithm.find("SHA256")) {
        return SGD_SHA256;
    } else if (algorithm.find("SM3")) {
        return SGD_SM3;
    }
    return 0;
}

int CY_SAF_Pkcs12_EncodeData(
        void *hAppHandle,
        unsigned char *pucSignerCertificate,
        unsigned int uiSignerCertificateLen,
        unsigned char *pucCertificateChain,
        unsigned int uiCertificateChainLen,
        unsigned char *pucDerPrivateKey,
        unsigned int uiDerPrivateKeyLen,
        const char *pcPassword,
        unsigned char *pucDerP12Data,
        unsigned int *puiDerP12DataLen)
{
    std::vector<unsigned char> vPrivateKey, vCertificate, vDerData;
    std::string sCertificateChain;
    AsymmetricKey::ptr asymmetric;
    X509Pkcs12::ptr pkcs12;
    DCHECK_NUL(hAppHandle, pucSignerCertificate,
               pucCertificateChain, pucDerPrivateKey, pucDerP12Data, puiDerP12DataLen);
    vPrivateKey.assign(pucDerPrivateKey, pucDerPrivateKey + uiDerPrivateKeyLen);
    vCertificate.assign(pucSignerCertificate, pucSignerCertificate + uiSignerCertificateLen);
    sCertificateChain.assign(pucCertificateChain, pucCertificateChain + uiCertificateChainLen);
    pkcs12 = X509Pkcs12::Create();
    if (pkcs12 == nullptr) {
        return error::Code::UnknownErr;
    }
    pkcs12->SetPassword(pcPassword);
    pkcs12->SetPrivateKey(vPrivateKey);
    pkcs12->SetCertificate(vCertificate);
    pkcs12->SetCertificateChain(sCertificateChain);
    pkcs12->GenerateStruct();
    pkcs12->GetDerEncode(&vDerData);
    if (vDerData.size() > *puiDerP12DataLen) {
        return error::Code::IndataLenErr;
    }
    memcpy(pucDerP12Data, vDerData.data(), vDerData.size());
    *puiDerP12DataLen = vDerData.size();
    return error::Code::Ok;
}

int CY_SAF_SM2_EncodeSignedAndEnvelopedData(
        void *hAppHandle,
        unsigned char *pucSignContainerName,
        unsigned int uiSignContainerNameLen,
        unsigned char *pucSignerCertificate,
        unsigned int uiSignerCertificateLen,
        unsigned int uiDigestAlgorithm,
        unsigned char *pucEncCertificate,
        unsigned int uiEncCertificateLen,
        unsigned int uiSymmAlgorithm,
        unsigned char *pucData,
        unsigned int uiDataLen,
        unsigned char *pucDerSignedAndEnvelopedData,
        unsigned int *puiDerSignedAndEnvelopedDataLen)
{
    DCHECK_NUL(hAppHandle, pucSignContainerName,
               pucSignerCertificate, pucEncCertificate, pucData,
               pucDerSignedAndEnvelopedData, puiDerSignedAndEnvelopedDataLen);
    (void)uiSignContainerNameLen;
    (void)uiSignerCertificateLen;
    (void)uiDigestAlgorithm;
    (void)uiEncCertificateLen;
    (void)uiSymmAlgorithm;
    (void)uiDataLen;
    return error::Code::NotSupportYetErr;
}

int CY_SAF_SM2_DecodeSignedAndEnvelopedData(
        void *hAppHandle,
        unsigned char *pucDerContainerName,
        unsigned int uiDerContainerNameLen,
        unsigned char *pucDerSignedAndEnvelopedData,
        unsigned int uiDerSignedAndEnvelopedDataLen,
        unsigned char *pucData,
        unsigned int *puiDataLen,
        unsigned char *pucSignerCertificate,
        unsigned int *puiSignerCertificateLen,
        unsigned int *puiDigestAlgorithm)
{
    DCHECK_NUL(hAppHandle, pucDerContainerName, pucDerSignedAndEnvelopedData,
               pucData, puiDataLen,
               pucSignerCertificate, puiSignerCertificateLen, puiDigestAlgorithm);
    (void)uiDerContainerNameLen;
    (void)uiDerSignedAndEnvelopedDataLen;
    return error::Code::NotSupportYetErr;
}

int CY_SAF_SM2_EncodeSignedData(
        void *hAppHandle,
        unsigned char *pucSignContainerName,
        unsigned int uiSignContainerNameLen,
        unsigned int uiSignKeyUsage,
        unsigned char *pucSignerCertificate,
        unsigned int uiSignerCertificateLen,
        unsigned int uiDigestAlgorithm,
        unsigned char *pucData,
        unsigned int uiDataLen,
        unsigned char *pucDerSignedData,
        unsigned int *puiDerSignedDataLen)
{
    DCHECK_NUL(hAppHandle, pucSignContainerName, pucSignerCertificate,
               pucData, pucDerSignedData, puiDerSignedDataLen);
    (void)uiSignKeyUsage;
    (void)uiSignContainerNameLen;
    (void)uiSignerCertificateLen;
    (void)uiDigestAlgorithm;
    (void)uiDataLen;
    return error::Code::NotSupportYetErr;
}

int CY_SAF_SM2_DecodeSignedData(
        void *hAppHandle,
        unsigned char *pucDerSignedData,
        unsigned int uiDerSignedDataLen,
        unsigned int *puiDigestAlgorithm,
        unsigned char *pucSignerCertificate,
        unsigned int *puiSignerCertificateLen,
        unsigned char *pucData,
        unsigned int *puiDataLen,
        unsigned char *pucSign,
        unsigned int *puiSignLen)
{
    DCHECK_NUL(hAppHandle, pucDerSignedData, puiDigestAlgorithm,
               pucSignerCertificate, puiSignerCertificateLen, pucData,
               puiDataLen, pucSign, puiSignLen);
    (void)uiDerSignedDataLen;
    return error::Code::NotSupportYetErr;
}

int CY_SAF_SM2_EncodeEnvelopedData(
        void *hAppHandle,
        unsigned char *pucData,
        unsigned int uiDataLen,
        unsigned char *pucEncCertificate,
        unsigned int uiEncCertificateLen,
        unsigned int uiSymmAlgorithm,
        unsigned char *pucDerEnvelopedData,
        unsigned int *puiDerEnvelopedDataLen)
{
    DCHECK_NUL(hAppHandle, pucData, pucEncCertificate,
               pucDerEnvelopedData, puiDerEnvelopedDataLen);
    (void)uiDataLen;
    (void)uiEncCertificateLen;
    (void)uiSymmAlgorithm;
    return error::Code::NotSupportYetErr;
}

int CY_SAF_SM2_DecodeEnvelopedData(
        void *hAppHandle,
        unsigned char *pucDecContainerName,
        unsigned int uiDecContainerNameLen,
        unsigned char *pucDerEnvelopedData,
        unsigned int uiDerEnvelopedDataLen,
        unsigned char *pucData,
        unsigned int *puiDataLen)
{
    DCHECK_NUL(hAppHandle, pucDecContainerName, pucDerEnvelopedData,
               pucData, puiDataLen);
    (void)uiDecContainerNameLen;
    (void)uiDerEnvelopedDataLen;
    return error::Code::NotSupportYetErr;
}