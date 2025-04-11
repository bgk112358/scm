//
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//

#ifndef SCM_CYBER_SAF_H
#define SCM_CYBER_SAF_H

#include <stdint.h>
#include "cyber_error.h"
#include "cyber_define.h"

/* ******************************************
           Environment interface
 ****************************************** */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Struct_Application {
    const char *AppPath;
} Application_st;

int CY_SAF_Initialize(
        void **phAppHandle,
        Application_st *pApplication);

int CY_SAF_Finalize(
        void *hAppHandle);

int CY_SAF_GetVersion(
        char *pcVersion);

int CY_SAF_Login(
        void *hAppHandle,
        unsigned int uiUsrType,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        unsigned int *puiRemainCount);

int CY_SAF_ChangePin(
        void *hAppHandle,
        unsigned int uiUsrType,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucOldPin,
        unsigned int uiOldPinLen,
        unsigned char *pucNewPin,
        unsigned int uiNewPinLen,
        unsigned int *puiRemainCount);

int CY_SAF_Logout(
        void *hAppHandle,
        unsigned int uiUsrType);

/* ******************************************
           Certificate interface
 ****************************************** */

int CY_SAF_AddTrustedCaCertificate(
        void *hAppHandle,
        const unsigned char *pucCertificate,
        unsigned int uiCertificateLen);

int CY_SAF_GetTrustedCaCertificateCount(
        void *hAppHandle,
        unsigned int *puiCount);

int CY_SAF_GetTrustedCaCertificate(
        void *hAppHandle,
        unsigned int uiIndex,
        unsigned char *pucCertificate,
        unsigned int *puiCertificateLen);

int CY_SAF_VerifyTrustedCaCertificate(
        void *hAppHandle,
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen);

int CY_SAF_RemoveTrustedCaCertificate(
        void *hAppHandle,
        unsigned int uiIndex);

int CY_SAF_GenerateCertificateSigningRequest(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        SGD_NAME_INFO *pstNameInfo,
        unsigned char *pucDerCertificateRequest,
        unsigned int *puiDerCertificateRequestLen);

int CY_SAF_ImportCertificateSigningRequest(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int  uiContainerNameLen,
        unsigned char *pucUsrCsr,
        unsigned int  uiUsrCsrLen);

int CY_SAF_ExportCertificateSigningRequest(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int  uiContainerNameLen,
        unsigned char *pucUsrCsr,
        unsigned int  *uiUsrCsrLen);

int CY_SAF_GetCertificateStatus(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int   uiContainerNameLen);

int CY_SAF_CheckCertificateKeyMatcher(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiSignFlag);

int CY_SAF_CheckCertificateAvailable(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiSignFlag,
        unsigned char *pucCertificate,
        unsigned int *uiCertificateLen);

int CY_SAF_ImportCertificate(
        void  *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int  uiContainerNameLen,
        unsigned int  uiSignFlag,
        unsigned char *pucUsrCertificate,
        unsigned int  uiUsrCertificateLen);

int CY_SAF_ImportCertificateEx(
        void  *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int  uiContainerNameLen,
        unsigned int  uiSignFlag,
        unsigned char *pucAlias,
        unsigned int  uiAliasLen,
        unsigned char *pucUsrCertificate,
        unsigned int  uiUsrCertificateLen);

int CY_SAF_ExportCertificate(
        void  *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int  uiContainerNameLen,
        unsigned int  uiSignFlag,
        unsigned char *pucUsrCertificate,
        unsigned int  *puiUsrCertificateLen);

int CY_SAF_RemoveCertificate(
        void  *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiSignFlag);

int CY_SAF_ExportP12Certificate(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int  uiContainerNameLen,
        const char    *pcPassword,
        unsigned char *pucCertificate,
        unsigned int  *uiCertificateLen);

int CY_SAF_DownloadCrl(
        void *hAppHandle,
        const char *crl_url,
        unsigned char *pucDerCrl,
        unsigned int *uiDerCrlLen);

int CY_SAF_VerifyCertificate(
        void *hAppHandle,
        unsigned char *pucUsrCertificate,
        unsigned int uiUsrCertificateLen);

int CY_SAF_VerifyCertificateByCrl(
        void *hAppHandle,
        unsigned char *pucUsrCertificate,
        unsigned int uiUsrCertificateLen,
        unsigned char *pucDerCrl,
        unsigned int uiDerCrlLen);

int CY_SAF_GetCertificateStateByOCSP(
        void *hAppHandle,
        unsigned char *pcOcspHostURL,
        unsigned int uiOcspHostURLLen,
        unsigned char *pucUsrCertificate,
        unsigned int uiUsrCertificateLen,
        unsigned char *pucCACertificate,
        unsigned int uiCACertificateLen);

int CY_SAF_GetCertificateInfo(
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        unsigned int uiInfoType,
        unsigned char *pucInfo,
        unsigned int *puiInfoLen);

int CY_SAF_GetCertificateKeyUsage(
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        unsigned int *puiUsage);

/* ******************************************
      Cryptographic algorithm interface
 ****************************************** */

int CY_SAF_Base64_Encode(
        unsigned char *pucInData,
        unsigned int  uiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen);

int CY_SAF_Base64_Decode(
        unsigned char *pucInData,
        unsigned int puiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen);

int CY_SAF_GenRandom(
        unsigned int uiRandLen,
        unsigned char *pucRand);

int CY_SAF_Hash(
        unsigned int uiHashAlgoType,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        unsigned char *pubID,
        unsigned int ulIDLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen);

int CY_SAF_HashFile(
        unsigned int uiHashAlgoType,
        const char *pcFileName,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen);

int CY_SAF_CreateHashObj(
        void **phHashObj,
        unsigned int uiHashAlgoType,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        unsigned char *pucID,
        unsigned int ulIDLen);

int CY_SAF_DestroyHashObj(
        void *hHashObj);

int CY_SAF_HashUpdate(
        void *hHashObj,
        const unsigned char *pucInData,
        unsigned int uiInDataLen);

int CY_SAF_HashFinal(
        void *hHashObj,
        unsigned char *pucOutData,
        unsigned int *uiOutDataLen);

int CY_SAF_GenRsaKeyPair(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiKeyBits,
        unsigned int uiKeyUsage,
        unsigned int uiExportFlag);

int CY_SAF_ImportRsaPublicKey(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiKeyUsage,
        unsigned int uiExportFlag,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen);

int CY_SAF_ImportRsaPrivateKey(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiKeyUsage,
        unsigned int uiExportFlag,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        unsigned char *pucPrivateKey,
        unsigned int uiPrivateKeyLen);

int CY_SAF_GetRsaPublicKey(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiKeyUsage,
        unsigned char *pucPublicKey,
        unsigned int *puiPublicKeyLen);

int CY_SAF_RsaSign(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiHashAlgoType,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen);

int CY_SAF_RsaSignPss(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiHashAlgoType,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen);

int CY_SAF_RsaSignFile(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiHashAlgoType,
        const char *pucFileName,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen);

int CY_SAF_RsaSignFilePss(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiHashAlgoType,
        const char *pucFileName,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen);

int CY_SAF_RsaVerifySign(
        unsigned int uiHashAlgoType,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen);

int CY_SAF_RsaVerifySignPss(
        unsigned int uiHashAlgoType,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen);

int CY_SAF_RsaVerifySignFile(
        unsigned int uiHashAlgoType,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        const char *pcFileName,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen);

int CY_SAF_RsaVerifySignFilePss(
        unsigned int uiHashAlgoType,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        const char *pcFileName,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen);

int CY_SAF_RsaVerifySignByCert(
        unsigned int uiHashAlgoType,
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen);

int CY_SAF_RsaVerifySignByCertPss(
        unsigned int uiHashAlgoType,
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen);

int CY_SAF_RsaVerifySignFileByCert(
        unsigned int uiHashAlgoType,
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        const char *pcFileName,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen);

int CY_SAF_RsaVerifySignFileByCertPss(
        unsigned int uiHashAlgoType,
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        const char *pcFileName,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen);

int CY_SAF_RsaEncrypt(
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int  *puiDataLen);

int CY_SAF_RsaEncryptByCert(
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int *uiDataLen);

int CY_SAF_RsaDecrypt(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int *puiDataLen);

int CY_SAF_GenEccKeyPair(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiAlgorithmID,
        unsigned int uiKeyUsage,
        unsigned int uiExportFlag);

int CY_SAF_ImportEccPublicKey(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiAlgorithm,
        unsigned int uiKeyUsage,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen);

int CY_SAF_ImportEccPrivateKey(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiAlgorithm,
        unsigned int uiKeyUsage,
        unsigned char *pucPrivateKey,
        unsigned int uiPrivateKeyLen);

int CY_SAF_GetEccPublicKey(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiKeyUsage,
        unsigned char *pucPublicKey,
        unsigned int *puiPublicKeyLen);

int CY_SAF_EccSign(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiHashAlgoType,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen);

int CY_SAF_EccSignFile(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiHashAlgoType,
        const char *pucFileName,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen);

int CY_SAF_EccVerifySign(
        unsigned int uiHashAlgoType,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen);

int CY_SAF_EccVerifySignFile(
        unsigned int uiHashAlgoType,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        const char *pucFileName,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen);

int CY_SAF_EccEncrypt(
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int  *puiDataLen);

int CY_SAF_EccEncryptByCert(
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int *uiDataLen);

int CY_SAF_EccDecrypt(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int *puiDataLen);

int CY_SAF_Sm2DecryptKeyBlob(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int *puiDataLen);

int CY_SAF_EccVerifySignByCert(
        unsigned int uiHashAlgoType,
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen);

int CY_SAF_CreateSymmKeyObj(
        void **phSymmKeyObj,
        unsigned char *pucKey,
        unsigned int  uiKeyLen,
        unsigned char *pucIV,
        unsigned int  uiIVLen,
        unsigned int  uiEncOrDec,
        unsigned int  uiCryptoAlgID);

int CY_SAF_GenerateAgreementDataWithECC(
        void *hSymmKeyObj,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiKeyBits,
        unsigned char *pucSponsorID,
        unsigned int uiSponsorIDLength,
        unsigned char *pucSponsorPublicKey,
        unsigned int *puiSponsorPublicKeyLen,
        unsigned char *pucSponsorTmpPublicKey,
        unsigned int *puiSponsorTmpPublicKeyLen,
        void **phAgreementHandle);

int CY_SAF_GenerateKeyWithECC(
        void *phAgreementHandle,
        unsigned char *pucResponseID,
        unsigned int uiResponseIDLength,
        unsigned char *pucResponsePublicKey,
        unsigned int uiResponsePublicKeyLen,
        unsigned char *pucResponseTmpPublicKey,
        unsigned int uiResponseTmpPublicKeyLen,
        void **phKeyHandle);

int CY_SAF_GenerateAgreementDataAdnKeyWithECC(
        void *hSymmKeyObj,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiKeyBits,
        unsigned char *pucResponseID,
        unsigned int uiResponseIDLength,
        unsigned char *pucSponsorID,
        unsigned int uiSponsorIDLength,
        unsigned char *pucSponsorPublicKey,
        unsigned int *puiSponsorPublicKeyLen,
        unsigned char *pucSponsorTmpPublicKey,
        unsigned int *puiSponsorTmpPublicKeyLen,
        unsigned char *pucResponsePublicKey,
        unsigned int uiResponsePublicKeyLen,
        unsigned char *pucResponseTmpPublicKey,
        unsigned int uiResponseTmpPublicKeyLen,
        void **phKeyHandle);

int CY_SAF_DestroySymmAlgoObj(
        void *hSymmKeyObj);

int CY_SAF_SymmEncrypt(
        void *hSymmKeyObj,
        const unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen);

int CY_SAF_SymmEncryptUpdate(
        void *hSymmKeyObj,
        const unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen);

int CY_SAF_SymmEncryptFinal(
        void *hSymmKeyObj,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen);

int CY_SAF_SymmDecrypt(
        void *hSymmKeyObj,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen);

int CY_SAF_SymmDecryptUpdate(
        void *hSymmKeyObj,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen);

int CY_SAF_SymmDecryptFinal(
        void *hSymmKeyObj,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen);

int CY_SAF_Hmac(
        unsigned int uiHashAlgoType,
        unsigned char * pucInKey,
        unsigned int uiInKeyLen,
        const unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen);

int CY_SAF_Hkdf(
        unsigned int uiHashAlgoType,
        unsigned char *pucIkm,
        unsigned int uiIkmLen,
        unsigned char *pucSaltData,
        unsigned int uiSaltDataLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucOutData,
        unsigned int puiOutDataLen);

/* ******************************************
            Message interface
 ****************************************** */
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
        unsigned int *puiDerP12DataLen);

/* ******************************************
           Internal Interface
 ****************************************** */
int CY_SAF_InternalGetContainerPath(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiContainerType,
        char *pcContainerPath,
        unsigned int uiContainerPathLen);

int CY_SAF_InternalWriteContainer(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int  uiContainerNameLen,
        unsigned int  uiContainerType,
        unsigned char *pucContainerData,
        unsigned int  uiContainerDataLen);

int CY_SAF_InternalReadContainer(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int  uiContainerNameLen,
        unsigned int  uiContainerType,
        unsigned char *pucPin,
        unsigned int  uiPinLen,
        unsigned int  *uiContainerUsage,
        unsigned char *pucContainerData,
        unsigned int  *uiContainerDataLen);

int CY_SAF_InternalImportPrivateKey(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int  uiSignFlag,
        unsigned char *pucData,
        unsigned int  *uiDataLen);

int CY_SAF_InternalExportPrivateKey(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int  uiSignFlag,
        unsigned int *uiAlgorithm,
        unsigned char *pucData,
        unsigned int  *uiDataLen);

#ifdef __cplusplus
};
#endif
#endif //SCM_CYBER_SAF_H
