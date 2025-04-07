//
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//

#include <stdio.h>
#include "cyber_pki.h"
#include "external/cyber_saf.h"
#include "external/cyber_thread.h"

/* ******************************************
           Environment interface
****************************************** */
int CY_InitService(
        void **phAppHandle,
        const char *pcAppFilePath) {
    CY_Lock(0);
    Application_st applicationSt;
    applicationSt.AppPath  = pcAppFilePath;
    int rv = CY_SAF_Initialize(
            phAppHandle,
            &applicationSt);
    CY_UnLock(0);
    return rv;
}

int CY_Finalize(
        void *hAppHandle) {
    CY_Lock(0);
    int rv = CY_SAF_Finalize(hAppHandle);
    CY_UnLock(0);
    return rv;
}

int CY_SetInitializeParameter(
        void *hAppHandle,
        const char *clientID,
        const char *token) {
    (void)hAppHandle;
    (void)clientID;
    (void)token;
//    return SC_SetInitializeParameter(hAppHandle, clientID, token);
    return -1;
}

int CY_GetVersion(
        char *pcVersion) {
    return CY_SAF_GetVersion(pcVersion);
}

/* ******************************************
           Certificate interface
 ****************************************** */

int CY_ImportTrustedCertificateChain(
        void *hAppHandle,
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen) {
    return CY_SAF_AddTrustedCaCertificate(
            hAppHandle,
            pucCertificate,
            uiCertificateLen);
}

int CY_GetTrustedCertificateChain(
        void *hAppHandle,
        unsigned char *pucCertificate,
        unsigned int *puiCertificateLen) {
    CY_Lock(0);
    int rv = CY_SAF_GetTrustedCaCertificate(
            hAppHandle,
            0,
            pucCertificate,
            puiCertificateLen);
    CY_UnLock(0);
    return rv;
}

int CY_RemoveTrustedCertificateChain(
        void *hAppHandle) {
    CY_Lock(0);
    int rv = CY_SAF_RemoveTrustedCaCertificate(hAppHandle, 0);
    CY_UnLock(0);
    return rv;
}

int CY_GenerateCertificateSigningRequest(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        SGD_NAME_INFO *pstNameInfo,
        unsigned char *pucDerCertificateRequest,
        unsigned int *puiDerCertificateRequestLen) {
    CY_Lock(0);
    unsigned int puiRemainCount = 0;
    int rv = CY_SAF_Login(
            hAppHandle,
            0,
            pucContainerName,
            uiContainerNameLen,
            pucPin,
            uiPinLen,
            &puiRemainCount);
    if (rv != CYBER_R_SUCCESS) {
        goto cleanup;
    }
    rv = CY_SAF_GenerateCertificateSigningRequest(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            pstNameInfo,
            pucDerCertificateRequest,
            puiDerCertificateRequestLen);
    if (rv != CYBER_R_SUCCESS) {
        goto cleanup;
    }
    rv = CY_SAF_Logout(
            hAppHandle,
            0);
cleanup:
    CY_UnLock(0);
    return rv;
}

int CY_GetCertificateStatus(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int   uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int   uiPinLen)
{
    CY_Lock(0);
    unsigned int puiRemainCount = 0;
    int rv = CY_SAF_Login(
            hAppHandle,
            0,
            pucContainerName,
            uiContainerNameLen,
            pucPin,
            uiPinLen,
            &puiRemainCount);
    if (rv != CYBER_R_SUCCESS) {
        goto cleanup;
    }
    rv = CY_SAF_GetCertificateStatus(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen);
    if (rv != CYBER_R_SUCCESS) {
        goto cleanup;
    }
    rv = CY_SAF_Logout(hAppHandle, 0);
cleanup:
    CY_UnLock(0);
    return rv;
}

int CY_ImportCertificate(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiSignFlag,
        unsigned char *pucUsrCertificate,
        unsigned int uiUserCertificateLen) {
    CY_Lock(0);
    int rv = CY_SAF_ImportCertificate(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiSignFlag,
            pucUsrCertificate,
            uiUserCertificateLen);
    CY_UnLock(0);
    return rv;
}

int CY_ExportCertificate(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiSignFlag,
        unsigned char *pucUsrCertificate,
        unsigned int *puiUserCertificate) {
    CY_Lock(0);
    int rv = CY_SAF_ExportCertificate(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiSignFlag,
            pucUsrCertificate,
            puiUserCertificate);
    CY_UnLock(0);
    return rv;
}

int CY_RemoveCertificate(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiSignFlag) {
    CY_Lock(0);
    int rv = CY_SAF_RemoveCertificate(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiSignFlag);
    CY_UnLock(0);
    return rv;
}

int CY_VerifyCertificate(
        void *hAppHandle,
        unsigned char *pucUsrCertificate,
        unsigned int uiUsrCertificateLen) {
    CY_Lock(0);
    int rv = CY_SAF_VerifyCertificate(
            hAppHandle,
            pucUsrCertificate,
            uiUsrCertificateLen);
    CY_UnLock(0);
    return rv;
}

int CY_VerifyCertificateByCrl(
        void *hAppHandle,
        unsigned char *pucUsrCertificate,
        unsigned int uiUsrCertificateLen,
        unsigned char *pucDerCrl,
        unsigned int uiDerCrlLen) {
    CY_Lock(0);
    int rv = CY_SAF_VerifyCertificateByCrl(
            hAppHandle,
            pucUsrCertificate,
            uiUsrCertificateLen,
            pucDerCrl,
            uiDerCrlLen);
    CY_UnLock(0);
    return rv;
}

int CY_GetCertificateStateByOCSP(
        void *hAppHandle,
        unsigned char *pcOcspHostURL,
        unsigned int uiOcspHostURLLen,
        unsigned char *pucUsrCertificate,
        unsigned int uiUsrCertificateLen,
        unsigned char *pucCACertificate,
        unsigned int uiCACertificateLen) {
    CY_Lock(0);
    int rv = CY_SAF_GetCertificateStateByOCSP(
            hAppHandle,
            pcOcspHostURL,
            uiOcspHostURLLen,
            pucUsrCertificate,
            uiUsrCertificateLen,
            pucCACertificate,
            uiCACertificateLen);
    CY_UnLock(0);
    return rv;
}

int CY_GetCertificateInfo(
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        unsigned int uiInfoType,
        unsigned char *pucInfo,
        unsigned int *puiInfoLen) {
    CY_Lock(0);
    int rv = CY_SAF_GetCertificateInfo(
            pucCertificate,
            uiCertificateLen,
            uiInfoType,
            pucInfo,
            puiInfoLen);
    CY_UnLock(0);
    return rv;
}

/******************** 密码运算接口 ********************/

int CY_Base64_Encode(
        unsigned char *pucInData,
        unsigned int puiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen) {
    return CY_SAF_Base64_Encode(pucInData, puiInDataLen, pucOutData,
                                puiOutDataLen);
}

int CY_Base64_Decode(
        unsigned char *pucInData,
        unsigned int puiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen) {
    return CY_SAF_Base64_Decode(pucInData, puiInDataLen, pucOutData,
                                puiOutDataLen);
}

int CY_GenRandom(
        unsigned int uiRandLen,
        unsigned char *pucRand) {
    return CY_SAF_GenRandom(uiRandLen, pucRand);
}

int CY_Hash(
        unsigned int uiAlgoType,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen) {
    return CY_SAF_Hash(uiAlgoType,
                       pucInData, uiInDataLen,
                       NULL, 0, NULL, 0,
                       pucOutData, puiOutDataLen);
}

int CY_CreateHashObj(
        void **phHashObj,
        unsigned int uiAlgoType) {
    return CY_SAF_CreateHashObj(phHashObj, uiAlgoType, NULL, 0, NULL, 0);
}

int CY_DestroyHashObj(
        void *phHashObj) {
    return CY_SAF_DestroyHashObj(phHashObj);
}

int CY_HashUpdate(
        void *hHashObj,
        unsigned char *pucInData,
        unsigned int uiInDataLen) {
    return CY_SAF_HashUpdate(hHashObj, pucInData, uiInDataLen);
}

int CY_HashFinal(
        void *hHashObj,
        unsigned char *pucOutData,
        unsigned int *uiOutDataLen) {
    return CY_SAF_HashFinal(hHashObj, pucOutData, uiOutDataLen);
}

int CY_GenRsaKeyPair(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        unsigned int uiKeyBits,
        unsigned int uiKeyUsage,
        unsigned int uiExportFlag) {
    CY_Lock(0);
    unsigned int puiRemainCount = 0;
    int rv = CY_SAF_Login(
            hAppHandle,
            0,
            pucContainerName,
            uiContainerNameLen,
            pucPin,
            uiPinLen,
            &puiRemainCount);
    if (rv != CYBER_R_SUCCESS) {
        goto cleanup;
    }
    rv = CY_SAF_GenRsaKeyPair(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiKeyBits,
            uiKeyUsage,
            uiExportFlag);
    if (rv != CYBER_R_SUCCESS) {
        goto cleanup;
    }
cleanup:
    CY_SAF_Logout(hAppHandle, 0);
    CY_UnLock(0);
    return rv;
}

int CY_GetRsaPublicKey(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiKeyUsage,
        unsigned char *pucPublicKey,
        unsigned int *puiPublicKeyLen) {
    CY_Lock(0);
    int rv = CY_SAF_GetRsaPublicKey(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiKeyUsage,
            pucPublicKey,
            puiPublicKeyLen);
    CY_UnLock(0);
    return rv;
}

int CY_RsaSign(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        unsigned int uiHashAlgoType,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen) {
    CY_Lock(0);
    int rv = CY_SAF_Login(
            hAppHandle,
            0,
            pucContainerName,
            uiContainerNameLen,
            pucPin,
            uiPinLen,
            NULL);
    if (rv != CYBER_R_SUCCESS) {
        goto cleanup;
    }
    rv = CY_SAF_RsaSign(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiHashAlgoType,
            pucInData,
            uiInDataLen,
            pucSignature,
            puiSignatureLen);
cleanup:
    CY_SAF_Logout(
            hAppHandle,
            0);
    CY_UnLock(0);
    return rv;
}

int CY_RsaSignPss(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        unsigned int uiHashAlgoType,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen)
{
    CY_Lock(0);
    int rv = CY_SAF_Login(
            hAppHandle,
            0,
            pucContainerName,
            uiContainerNameLen,
            pucPin,
            uiPinLen,
            NULL);
    if (rv != CYBER_R_SUCCESS) {
        goto cleanup;
    }
    rv = CY_SAF_RsaSignPss(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiHashAlgoType,
            pucInData,
            uiInDataLen,
            pucSignature,
            puiSignatureLen);
cleanup:
    CY_SAF_Logout(
            hAppHandle,
            0);
    CY_UnLock(0);
    return rv;
}

int CY_RsaSignFile(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        unsigned int uiHashAlgoType,
        const char *pucFileName,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen) {
    CY_Lock(0);
    int rv = CY_SAF_Login(
            hAppHandle,
            0,
            pucContainerName,
            uiContainerNameLen,
            pucPin,
            uiPinLen,
            NULL);
    if (rv != CYBER_R_SUCCESS) {
        goto cleanup;
    }
    rv = CY_SAF_RsaSignFile(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiHashAlgoType,
            pucFileName,
            pucSignature,
            puiSignatureLen);
cleanup:
    CY_SAF_Logout(
            hAppHandle,
            0);
    CY_UnLock(0);
    return rv;
}

int CY_RsaSignFilePss(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        unsigned int uiHashAlgoType,
        const char *pcFileName,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen)
{
    CY_Lock(0);
    int rv = CY_SAF_Login(
            hAppHandle,
            0,
            pucContainerName,
            uiContainerNameLen,
            pucPin,
            uiPinLen,
            NULL);
    if (rv != CYBER_R_SUCCESS) {
        goto cleanup;
    }
    rv = CY_SAF_RsaSignFilePss(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiHashAlgoType,
            pcFileName,
            pucSignature,
            puiSignatureLen);
    cleanup:
    CY_SAF_Logout(
            hAppHandle,
            0);
    CY_UnLock(0);
    return rv;
}

int CY_RsaVerifySign(
        unsigned int uiHashAlgoType,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignData,
        unsigned int uiSignDataLen) {
    CY_Lock(0);
    int rv = CY_SAF_RsaVerifySign(
            uiHashAlgoType,
            pucPublicKey,
            uiPublicKeyLen,
            pucInData,
            uiInDataLen,
            pucSignData,
            uiSignDataLen);
    CY_UnLock(0);
    return rv;
}

int CY_RsaVerifySignPss(
        unsigned int uiHashAlgoType,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignData,
        unsigned int uiSignDataLen)
{
    CY_Lock(0);
    int rv = CY_SAF_RsaVerifySignPss(
            uiHashAlgoType,
            pucPublicKey,
            uiPublicKeyLen,
            pucInData,
            uiInDataLen,
            pucSignData,
            uiSignDataLen);
    CY_UnLock(0);
    return rv;
}

int CY_RsaVerifySignFile(
        unsigned int uiHashAlgoType,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        const char *pucFileName,
        unsigned char *pucSignData,
        unsigned int uiSignDataLen) {
    CY_Lock(0);
    int rv = CY_SAF_RsaVerifySignFile(
            uiHashAlgoType,
            pucPublicKey,
            uiPublicKeyLen,
            pucFileName,
            pucSignData,
            uiSignDataLen);
    CY_UnLock(0);
    return rv;
}

int CY_RsaVerifySignFilePss(
        unsigned int uiHashAlgoType,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        const char *pucFileName,
        unsigned char *pucSignData,
        unsigned int uiSignDataLen) {
    CY_Lock(0);
    int rv = CY_SAF_RsaVerifySignFilePss(
            uiHashAlgoType,
            pucPublicKey,
            uiPublicKeyLen,
            pucFileName,
            pucSignData,
            uiSignDataLen);
    CY_UnLock(0);
    return rv;
}

int CY_RsaVerifySignByCert(
        unsigned int uiHashAlgoType,
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignData,
        unsigned int uiSignDataLen) {
    CY_Lock(0);
    int rv = CY_SAF_RsaVerifySignByCert(
            uiHashAlgoType,
            pucCertificate,
            uiCertificateLen,
            pucInData,
            uiInDataLen,
            pucSignData,
            uiSignDataLen);
    CY_UnLock(0);
    return rv;
}

int CY_RsaVerifySignByCertPss(
        unsigned int uiHashAlgoType,
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignData,
        unsigned int uiSignDataLen) {
    CY_Lock(0);
    int rv = CY_SAF_RsaVerifySignByCertPss(
            uiHashAlgoType,
            pucCertificate,
            uiCertificateLen,
            pucInData,
            uiInDataLen,
            pucSignData,
            uiSignDataLen);
    CY_UnLock(0);
    return rv;
}

int CY_RsaVerifySignFileByCert(
        unsigned int uiHashAlgoType,
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        const char *pcFileName,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen) {
    CY_Lock(0);
    int rv = CY_SAF_RsaVerifySignFileByCert(
            uiHashAlgoType,
            pucCertificate,
            uiCertificateLen,
            pcFileName,
            pucSignature,
            uiSignatureLen);
    CY_UnLock(0);
    return rv;
}

int CY_RsaVerifySignFileByCertPss(
        unsigned int uiHashAlgoType,
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        const char *pcFileName,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen) {
    CY_Lock(0);
    int rv = CY_SAF_RsaVerifySignFileByCertPss(
            uiHashAlgoType,
            pucCertificate,
            uiCertificateLen,
            pcFileName,
            pucSignature,
            uiSignatureLen);
    CY_UnLock(0);
    return rv;
}

int CY_RsaEncrypt(
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int  *puiDataLen)
{
    CY_Lock(0);
    int rv = CY_SAF_RsaEncrypt(
            pucPublicKey,
            uiPublicKeyLen,
            pucInData,
            uiInDataLen,
            pucData,
            puiDataLen);
    CY_UnLock(0);
    return rv;
}

int CY_RsaEncryptByCert(
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int *uiDataLen)
{
    CY_Lock(0);
    int rv = CY_SAF_RsaEncryptByCert(
            pucCertificate,
            uiCertificateLen,
            pucInData,
            uiInDataLen,
            pucData,
            uiDataLen);
    CY_UnLock(0);
    return rv;
}

int CY_RsaDecrypt(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int *puiDataLen)
{
    CY_Lock(0);
    unsigned int puiRemainCount = 0;
    int rv = CY_SAF_Login(
            hAppHandle,
            0,
            pucContainerName,
            uiContainerNameLen,
            pucPin,
            uiPinLen,
            &puiRemainCount);
    if (rv != CYBER_R_SUCCESS) {
        goto cleanup;
    }
    rv = CY_SAF_RsaDecrypt(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            pucInData,
            uiInDataLen,
            pucData,
            puiDataLen);
cleanup:
    CY_SAF_Logout(hAppHandle, 0);
    CY_UnLock(0);
    return rv;
}

int CY_GenEccKeyPair(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        unsigned int uiAlgorithmID,
        unsigned int uiKeyUsage,
        unsigned int uiExportFlag) {
    CY_Lock(0);
    unsigned int puiRemainCount = 0;
    int rv = CY_SAF_Login(
            hAppHandle,
            0,
            pucContainerName,
            uiContainerNameLen,
            pucPin,
            uiPinLen,
            &puiRemainCount);
    if (rv != CYBER_R_SUCCESS) {
        goto cleanup;
    }
    rv = CY_SAF_GenEccKeyPair(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiAlgorithmID,
            uiKeyUsage,
            uiExportFlag);
cleanup:
    CY_SAF_Logout(hAppHandle, 0);
    CY_UnLock(0);
    return rv;
}

int CY_GetEccPublicKey(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiKeyUsage,
        unsigned char *pucPublicKey,
        unsigned int *puiPublicKeyLen) {
    CY_Lock(0);
    int rv = CY_SAF_GetEccPublicKey(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiKeyUsage,
            pucPublicKey,
            puiPublicKeyLen);
    CY_UnLock(0);
    return rv;
}

int CY_EccSign(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        unsigned int uiHashAlgoType,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen) {
    CY_Lock(0);
    unsigned int puiRemainCount = 0;
    int rv = CY_SAF_Login(
            hAppHandle,
            0,
            pucContainerName,
            uiContainerNameLen,
            pucPin,
            uiPinLen,
            &puiRemainCount);
    if (rv != CYBER_R_SUCCESS) {
        goto cleanup;
    }
    rv = CY_SAF_EccSign(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiHashAlgoType,
            pucInData,
            uiInDataLen,
            pucSignature,
            puiSignatureLen);
cleanup:
    CY_SAF_Logout(
            hAppHandle,
            0);
    CY_UnLock(0);
    return rv;
}

int CY_EccSignFile(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        unsigned int uiHashAlgoType,
        const char *pcFileName,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen) {
    CY_Lock(0);
    unsigned int puiRemainCount = 0;
    int rv = CY_SAF_Login(
            hAppHandle,
            0,
            pucContainerName,
            uiContainerNameLen,
            pucPin,
            uiPinLen,
            &puiRemainCount);
    if (rv != CYBER_R_SUCCESS) {
        goto cleanup;
    }
    rv = CY_SAF_EccSignFile(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiHashAlgoType,
            pcFileName,
            pucSignature,
            puiSignatureLen);
cleanup:
    CY_SAF_Logout(
            hAppHandle,
            0);
    CY_UnLock(0);
    return rv;
}

int CY_EccVerifySign(
        unsigned int uiHashAlgoType,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignData,
        unsigned int uiSignDataLen) {
    CY_Lock(0);
    int rv = CY_SAF_EccVerifySign(
            uiHashAlgoType,
            pucPublicKey,
            uiPublicKeyLen,
            pucInData,
            uiInDataLen,
            pucSignData,
            uiSignDataLen);
    CY_UnLock(0);
    return rv;
}

int CY_EccVerifySignFile(
        unsigned int uiHashAlgoType,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        const char *pucFileName,
        unsigned char *pucSignData,
        unsigned int uiSignDataLen) {
    CY_Lock(0);
    int rv = CY_SAF_EccVerifySignFile(
            uiHashAlgoType,
            pucPublicKey,
            uiPublicKeyLen,
            pucFileName,
            pucSignData,
            uiSignDataLen);
    CY_UnLock(0);
    return rv;
}

int CY_EccVerifySignByCert(
        unsigned int uiHashAlgoType,
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignData,
        unsigned int uiSignDataLen) {
    CY_Lock(0);
    int rv = CY_SAF_EccVerifySignByCert(
            uiHashAlgoType,
            pucCertificate,
            uiCertificateLen,
            pucInData,
            uiInDataLen,
            pucSignData,
            uiSignDataLen);
    CY_UnLock(0);
    return rv;
}

int CY_EccEncrypt(
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int  *puiDataLen)
{
    CY_Lock(0);
    int rv = CY_SAF_EccEncrypt(
            pucPublicKey,
            uiPublicKeyLen,
            pucInData,
            uiInDataLen,
            pucData,
            puiDataLen);
    CY_UnLock(0);
    return rv;
}

int CY_EccEncryptByCert(
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int *puiDataLen)
{
    int rv = CY_SAF_EccEncryptByCert(
            pucCertificate,
            uiCertificateLen,
            pucInData,
            uiInDataLen,
            pucData,
            puiDataLen);
    CY_UnLock(0);
    return rv;
}

int CY_EccDecrypt(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int *puiDataLen)
{
    CY_Lock(0);
    unsigned int puiRemainCount = 0;
    int rv = CY_SAF_Login(
            hAppHandle,
            0,
            pucContainerName,
            uiContainerNameLen,
            pucPin,
            uiPinLen,
            &puiRemainCount);
    if (rv != CYBER_R_SUCCESS) {
        goto cleanup;
    }
    rv = CY_SAF_EccDecrypt(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            pucInData,
            uiInDataLen,
            pucData,
            puiDataLen);
cleanup:
    CY_SAF_Logout(hAppHandle, 0);
    CY_UnLock(0);
    return rv;
}


int CY_CreateSymmKeyObj(
        void **phSymmKeyObj,
        unsigned char *pucKey,
        unsigned int uiKeyLen,
        unsigned char *pucIV,
        unsigned int uiIVLen,
        unsigned int uiEncOrDec,
        unsigned int uiCryptoAlgID) {
    return CY_SAF_CreateSymmKeyObj(
            phSymmKeyObj,
            pucKey,
            uiKeyLen,
            pucIV,
            uiIVLen,
            uiEncOrDec,
            uiCryptoAlgID);
}

int CY_DestroySymmKeyObj(
        void *hSymmKeyObj) {
    return CY_SAF_DestroySymmAlgoObj(hSymmKeyObj);
}

int CY_SymmEncrypt(
        void *hSymmKeyObj,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen) {
    return CY_SAF_SymmEncrypt(
            hSymmKeyObj,
            pucInData,
            uiInDataLen,
            pucOutData,
            puiOutDataLen);
}

int CY_SymmEncryptUpdate(
        void *hSymmKeyObj,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen) {
    return CY_SAF_SymmEncryptUpdate(
            hSymmKeyObj,
            pucInData,
            uiInDataLen,
            pucOutData,
            puiOutDataLen);
}

int CY_SymmEncryptFinal(
        void *hSymmKeyObj,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen) {
    return CY_SAF_SymmEncryptFinal(
            hSymmKeyObj,
            pucOutData,
            puiOutDataLen);
}

int CY_SymmDecrypt(
        void *hSymmKeyObj,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen) {
    return CY_SAF_SymmDecrypt(
            hSymmKeyObj,
            pucInData,
            uiInDataLen,
            pucOutData,
            puiOutDataLen);
}

int CY_SymmDecryptUpdate(
        void *hSymmKeyObj,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen) {
    return CY_SAF_SymmDecryptUpdate(
            hSymmKeyObj,
            pucInData,
            uiInDataLen,
            pucOutData,
            puiOutDataLen);
}

int CY_SymmDecryptFinal(
        void *hSymmKeyObj,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen) {
    return CY_SAF_SymmDecryptFinal(
            hSymmKeyObj,
            pucOutData,
            puiOutDataLen);
}

int CY_Hmac(unsigned int uiHashAlgoType,
            unsigned char *pucKey,
            unsigned int uiKeyLen,
            unsigned char *pucInData,
            unsigned int uiInDataLen,
            unsigned char *pucOutData,
            unsigned int *puiOutDataLen) {
    return CY_SAF_Hmac(uiHashAlgoType,
                       pucKey, uiKeyLen,
                       pucInData, uiInDataLen,
                       pucOutData, puiOutDataLen);
}

int CY_Hkdf(unsigned int uiHashAlgoType,
            unsigned char *pucIkm,
            unsigned int uiIkmLen,
            unsigned char *pucSaltData,
            unsigned int uiSaltDataLen,
            unsigned char *pucInData,
            unsigned int uiInDataLen,
            unsigned char *pucOutData,
            unsigned int puiOutDataLen) {
    return CY_SAF_Hkdf(uiHashAlgoType,
                       pucIkm, uiIkmLen,
                       pucSaltData, uiSaltDataLen,
                       pucInData, uiInDataLen,
                       pucOutData, puiOutDataLen);
}