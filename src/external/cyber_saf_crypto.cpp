// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//

#include "cyber_saf.h"
#include "crypto/crypto.h"
#include "crypto/asymmetric_signer.h"
#include "crypto/asymmetric_encipher.h"
#include "crypto/encipher/sm2_enveloper.h"
#include "container/container_builder.h"
#include "handle/handler.h"
#include "util/util.h"
#include "../common/config.h"
#include "util/path_utils.h"

using namespace cyber;

int CY_SAF_Base64_Encode(
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen)
{
    DCHECK_NUL(pucInData, puiOutDataLen);
    std::string sEncode = Base64Encode(pucInData, uiInDataLen);
    if (pucOutData == nullptr) {
        *puiOutDataLen = sEncode.size();
        return error::Code::Ok;
    }
    if (*puiOutDataLen < sEncode.size()) {
        return error::Code::IndataLenErr;
    }
    memcpy(pucOutData, sEncode.c_str(), sEncode.size());
    *puiOutDataLen = sEncode.size();
    return error::Code::Ok;
}

int CY_SAF_Base64_Decode(
        unsigned char *pucInData,
        unsigned int puiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen)
{
    DCHECK_NUL(pucInData, puiOutDataLen);
    std::vector<unsigned char> vDecode = Base64Decode(pucInData, puiInDataLen);
    if (pucOutData == nullptr) {
        *puiOutDataLen = vDecode.size();
        return error::Code::Ok;
    }
    if (*puiOutDataLen < vDecode.size()) {
        return error::Code::IndataLenErr;
    }
    memcpy(pucOutData, vDecode.data(), vDecode.size());
    *puiOutDataLen = vDecode.size();
    return error::Code::Ok;
}

int CY_SAF_GenRandom(
        unsigned int uiRandLen,
        unsigned char *pucRand)
{
    DCHECK_NUL(pucRand);
    RandBytes(pucRand, uiRandLen);
    return error::Code::Ok;
}

int CY_SAF_Hash(
        unsigned int uiHashAlgoType,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        unsigned char *pubID,
        unsigned int uiIDLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen)
{
    (void)uiPublicKeyLen;
    (void)uiIDLen;
    DCHECK_NUL(pucInData, pucOutData, puiOutDataLen);
    int rv = error::Code::UnknownErr;
    std::string sAlgorithm;
    IDigest *iDigest = nullptr;
    FUNC_ENTRY;
    unsigned char pucHashData[64] = {0};
    unsigned int uiHashDataLen    = 64;
    switch (uiHashAlgoType) {
        case SGD_NONE:   sAlgorithm = "NONE";   break;
        case SGD_SHA1:   sAlgorithm = "SHA1";   break;
        case SGD_SHA256: sAlgorithm = "SHA256"; break;
        case SGD_SHA512: sAlgorithm = "SHA512"; break;
        case SGD_SM3:    sAlgorithm = "SM3";    break;
        default: rv = error::Code::AlgoTypeErr; goto cleanup;
    }
    FUNC_PARAMETER(sAlgorithm);
    if (uiHashAlgoType == SGD_NONE) {
        if (*puiOutDataLen < uiInDataLen) {
            rv = error::Code::IndataLenErr;
            goto cleanup;
        }
        memcpy(pucOutData, pucInData, uiInDataLen);
        *puiOutDataLen = uiInDataLen;
        rv = error::Code::Ok;
        goto cleanup;
    }
    iDigest = Digest::CreateDigest(sAlgorithm);
    if (iDigest == nullptr) {
        rv = error::Code::HashObjErr;
        goto cleanup;
    }
    if (!iDigest->Init() ||
        !iDigest->Update(pucInData, uiInDataLen) ||
        !iDigest->Final(pucHashData, &uiHashDataLen)) {
        rv = error::Code::HashErr;
        goto cleanup;
    }
    if (*puiOutDataLen < uiHashDataLen) {
        rv = error::Code::IndataLenErr;
        goto cleanup;
    }
    memcpy(pucOutData, pucHashData, uiHashDataLen);
    *puiOutDataLen = uiHashDataLen;
    rv = error::Code::Ok;
cleanup:
    FUNC_EXIT_RV(rv);
    delete iDigest;
    return rv;
}

int CY_SAF_HashFile(
        unsigned int uiHashAlgoType,
        const char *pcFileName,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen)
{
    DCHECK_NUL(pcFileName, pucOutData, puiOutDataLen);
    unsigned char ucBuffer[2048] = {0};
    unsigned char ucDigest[64] = {0};
    unsigned int  uiBufferLen, uiDigestLen = 64;
    BIO *pBio = nullptr;
    void *phHashObj = nullptr;
    int rv = CY_SAF_CreateHashObj(&phHashObj, uiHashAlgoType, nullptr, 0,
                                  nullptr, 0);
    if (rv != CYBER_R_SUCCESS) {
        return rv;
    }
    if (!(pBio = BIO_new_file((const char *)pcFileName, "rb"))) {
        rv = error::Code::FileNotFoundErr;
        goto cleanup;
    }
    while ((uiBufferLen = BIO_read(pBio, ucBuffer, sizeof(ucBuffer))) > 0) {
        CY_SAF_HashUpdate(phHashObj, ucBuffer, uiBufferLen);
    }
    rv = CY_SAF_HashFinal(phHashObj, ucDigest, &uiDigestLen);
    if (rv != CYBER_R_SUCCESS) {
        return rv;
    }
    if (*puiOutDataLen < uiDigestLen) {
        rv = error::Code::IndataLenErr;
        goto cleanup;
    }
    memcpy(pucOutData, ucDigest, uiDigestLen);
    *puiOutDataLen = uiDigestLen;
cleanup:
    CY_SAF_DestroyHashObj(phHashObj);
    BIO_free(pBio);
    return rv;
}

int CY_SAF_CreateHashObj(
        void **phHashObj,
        unsigned int uiHashAlgoType,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        unsigned char *pucID,
        unsigned int ulIDLen)
{
    IDigest *iDigest;
    std::string sAlgorithm;
    switch (uiHashAlgoType) {
        case SGD_NONE:   sAlgorithm = "NONE";   break;
        case SGD_SHA1:   sAlgorithm = "SHA1";   break;
        case SGD_SHA256: sAlgorithm = "SHA256"; break;
        case SGD_SHA512: sAlgorithm = "SHA512"; break;
        case SGD_SM3:    sAlgorithm = "SM3";    break;
        default: return error::Code::AlgoTypeErr;
    }
    iDigest = Digest::CreateDigest(sAlgorithm);
    if (iDigest == nullptr) {
        return error::Code::AlgoTypeErr;
    }
    if (!iDigest->Init()) {
        return error::Code::HashObjErr;
    }
    *phHashObj = iDigest;
    return error::Code::Ok;
}

int CY_SAF_DestroyHashObj(
        void *hHashObj)
{
    DCHECK_NUL(hHashObj);
    auto *hash = static_cast<IDigest *>(hHashObj);
    delete hash;
    return error::Code::Ok;
}

int CY_SAF_HashUpdate(
        void *hHashObj,
        const unsigned char *pucInData,
        unsigned int uiInDataLen)
{
    DCHECK_NUL(hHashObj, pucInData);
    auto *digest = static_cast<IDigest *>(hHashObj);
    if (!digest->Update(pucInData, uiInDataLen)) {
        return error::Code::HashErr;
    }
    return error::Code::Ok;
}

int CY_SAF_HashFinal(
        void *hHashObj,
        unsigned char *pucOutData,
        unsigned int *uiOutDataLen)
{
    DCHECK_NUL(hHashObj, pucOutData, uiOutDataLen);
    auto *digest = static_cast<IDigest *>(hHashObj);
    if (!digest->Final(pucOutData, uiOutDataLen)) {
        return error::Code::HashErr;
    }
    return error::Code::Ok;
}

int CY_SAF_GenRsaKeyPair(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiKeyBits,
        unsigned int uiKeyUsage,
        unsigned int uiExportFlag)
{
    DCHECK_NUL(hAppHandle, pucContainerName);
    int rv;
    auto *handle = static_cast<Handler *>(hAppHandle);
    std::shared_ptr<IKeyPair> iKeyPair;
    std::vector<unsigned char> vBuffer;
    std::string sContainerPin;
    FUNC_ENTRY;
    FUNC_PARAMETER(hAppHandle);
    FUNC_PARAMETER(pucContainerName);
    FUNC_PARAMETER(uiKeyBits);
    FUNC_PARAMETER(uiKeyUsage);
    // Initialization judgment
    if (!handle->isInitialized()) {
        rv = error::Code::NotInitializeErr;
        goto cleanup;
    }
    if (uiKeyBits != 2048 && uiKeyBits != 3072 && uiKeyBits != 4096) {
        rv = error::Code::RsaModulusLenErr;
        goto cleanup;
    }
    // Generate KeyPair
    iKeyPair = AsymmetricKey::CreateKeyPair("RSA");
    if (iKeyPair == nullptr) {
        rv = error::Code::UnknownErr;
        goto cleanup;
    }
    if (!iKeyPair->GenerateKeyPair((int) uiKeyBits, "RSA")) {
        rv = error::Code::GenKeyErr;
        goto cleanup;
    }
    // Storage PublicKey
    if (!iKeyPair->ExportDerPublicKey(vBuffer)) {
        rv = error::Code::KeyEncodeErr;
        goto cleanup;
    }
    rv = CY_SAF_ImportRsaPublicKey(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiKeyUsage,
            uiExportFlag,
            vBuffer.data(),
            vBuffer.size());
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    // Storage PrivateKey
    // If it is hardware, the public key is saved
    if (!handle->isHardWare()) {
        iKeyPair->ExportDerPrivateKey(vBuffer);
    }
    sContainerPin = handle->GetContainerPin();
    rv = CY_SAF_ImportRsaPrivateKey(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiKeyUsage,
            uiExportFlag,
            (unsigned char *) sContainerPin.data(),
            sContainerPin.size(),
            vBuffer.data(),
            vBuffer.size());
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_ImportRsaPublicKey(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiKeyUsage,
        unsigned int uiExportFlag,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen)
{
    DCHECK_NUL(hAppHandle, pucContainerName, pucPublicKey);
    int rv = error::Code::Ok;
    std::unique_ptr<Container> cContainer(new Container);
    std::string sContainerName(reinterpret_cast<const char *>(pucContainerName),
                               uiContainerNameLen);
    std::vector<unsigned char> vData;
    Container::Usage usage;
    unsigned int uiContainerType;
    if (uiKeyUsage == SGD_KEYUSAGE_SIGN) {
        uiContainerType = SIGN_PUB_KEY;
        usage = Container::SIGN;
    } else if (uiKeyUsage == SGD_KEYUSAGE_ENC) {
        uiContainerType = ENC_PUB_KEY;
        usage = Container::ENC;
    } else {
        return error::Code::KeyUsageErr;
    }
    vData.assign(pucPublicKey, pucPublicKey + uiPublicKeyLen);
    cContainer = ContainerBuilder()
            .SetStorageType(Container::PUBLIC_KEY)
            .SetContainerName(sContainerName)
            .SetUsage(usage)
            .SetAlgorithm(Container::RSA)
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
            uiContainerType,
            vData.data(),
            vData.size());
    return rv;
}

int CY_SAF_ImportRsaPrivateKey(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiKeyUsage,
        unsigned int uiExportFlag,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        unsigned char *pucPrivateKey,
        unsigned int uiPrivateKeyLen)
{
    DCHECK_NUL(hAppHandle, pucContainerName, pucPrivateKey);
    int rv = 0;
    Container::Usage usage;
    unsigned int uiContainerType;
    std::unique_ptr<Container> cContainer(new Container);
    std::string sContainerName;
    std::string sContainerPin;
    std::vector<unsigned char> vData;
    if (uiKeyUsage == SGD_KEYUSAGE_SIGN) {
        uiContainerType = SIGN_KEY;
        usage = Container::SIGN;
    } else if (uiKeyUsage == SGD_KEYUSAGE_ENC) {
        uiContainerType = ENC_KEY;
        usage = Container::ENC;
    } else {
        return error::Code::KeyUsageErr;
    }
    sContainerName.assign((const char *)pucContainerName, uiContainerNameLen);
    if (pucPin) {
        sContainerPin.assign((const char *)pucPin, uiPinLen);
    }
    vData.assign(pucPrivateKey, pucPrivateKey + uiPrivateKeyLen);
    cContainer = ContainerBuilder()
            .SetStorageType(Container::PRIVATE_KEY)
            .SetContainerName(sContainerName)
            .SetUsage(usage)
            .SetAlgorithm(Container::RSA)
            .SetContainerPin(sContainerPin)
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
            uiContainerType,
            vData.data(),
            vData.size());
    return rv;
}

int CY_SAF_GetRsaPublicKey(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiKeyUsage,
        unsigned char *pucPublicKey,
        unsigned int *uiPublicKeyLen)
{
    DCHECK_NUL(hAppHandle, pucContainerName);
    int rv;
    unsigned int uiContainerType;
    auto *handler = static_cast<Handler *>(hAppHandle);
    FUNC_ENTRY;
    FUNC_PARAMETER(pucContainerName);
    FUNC_PARAMETER(uiKeyUsage);
    // Initialization judgment
    if (!handler->isInitialized()) {
        rv = error::Code::NotInitializeErr;
        goto cleanup;
    }
    if (uiKeyUsage == SGD_KEYUSAGE_SIGN) {
        uiContainerType = SIGN_PUB_KEY;
    } else if (uiKeyUsage == SGD_KEYUSAGE_ENC) {
        uiContainerType = ENC_PUB_KEY;
    } else {
        rv = error::Code::KeyUsageErr;
        goto cleanup;
    }
    rv = CY_SAF_InternalReadContainer(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiContainerType,
            nullptr,
            0,
            nullptr,
            pucPublicKey,
            uiPublicKeyLen);
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_RsaSign(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiHashAlgoType,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen)
{
    DCHECK_NUL(hAppHandle, pucContainerName, pucInData, puiSignatureLen);
    int rv;
    unsigned char ucPrivateKey[3072] = {0};
    unsigned int  uiPrivateKeyLen = 3072;
    unsigned int  uiAlgorithm = 0;
    std::vector<unsigned char> vPrivateKey, vMessage, vSignature;
    auto *handler = static_cast<Handler *>(hAppHandle);
    std::shared_ptr<IKeyPair> iKeyPair;
    std::shared_ptr<ISigner> iSigner;
    std::string sAlgorithm;
    FUNC_ENTRY;
    FUNC_PARAMETER(pucContainerName);
    // Initialization judgment
    if (!handler->isInitialized()) {
        rv = error::Code::NotInitializeErr;
        goto cleanup;
    }
    switch (uiHashAlgoType) {
        case SGD_NONE:   sAlgorithm = "NONE";   break;
        case SGD_SHA1:   sAlgorithm = "SHA1";   break;
        case SGD_SHA256: sAlgorithm = "SHA256"; break;
        case SGD_SHA512: sAlgorithm = "SHA512"; break;
        default: return error::Code::AlgoTypeErr;
    }
    FUNC_PARAMETER(sAlgorithm);
    // Export private key
    rv = CY_SAF_InternalExportPrivateKey(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            1,
            &uiAlgorithm,
            ucPrivateKey,
            &uiPrivateKeyLen);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    iKeyPair = std::make_shared<RsaKeyPair>();
    if (!iKeyPair) {
        rv = error::Code::UnknownErr;
        goto cleanup;
    }
    vPrivateKey.assign(ucPrivateKey, ucPrivateKey + uiPrivateKeyLen);
    if (!iKeyPair->ImportDerPrivateKey(vPrivateKey) &&
        !iKeyPair->ImportDerPublicKey(vPrivateKey)) {
        rv = error::Code::KeyEncodeErr;
        goto cleanup;
    }
    vMessage.assign(pucInData, pucInData + uiInDataLen);
    iSigner = std::make_shared<RsaSigner>();
    if (!iSigner) {
        rv = error::Code::UnknownErr;
        goto cleanup;
    }
    // Make Signature
    if (!iSigner->MakeSignature(iKeyPair.get(), sAlgorithm, vMessage, vSignature)) {
        rv = error::Code::SignErr;
        goto cleanup;
    }
    if (pucSignature == nullptr) {
        *puiSignatureLen = vSignature.size();
        rv = error::Code::Ok;
        goto cleanup;
    }
    if (*puiSignatureLen < vSignature.size()) {
        rv = error::Code::IndataLenErr;
        goto cleanup;
    }
    memcpy(pucSignature, vSignature.data(), vSignature.size());
    *puiSignatureLen = vSignature.size();
    rv = error::Code::Ok;
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_RsaSignPss(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiHashAlgoType,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen)
{
    DCHECK_NUL(hAppHandle, pucContainerName, pucInData, puiSignatureLen);
    int rv;
    unsigned char pucPrivateKey[3072] = {0};
    unsigned int uiPrivateKeyLen = 3072;
    unsigned int uiAlgorithm = 0;
    std::vector<unsigned char> vPrivateKey, vMessage, vSignature;
    auto *handle = static_cast<Handler *>(hAppHandle);
    std::shared_ptr<IKeyPair> iKeyPair;
    std::shared_ptr<ISigner> iSigner;
    std::string hashAlgorithm;
    FUNC_ENTRY;
    FUNC_PARAMETER(pucContainerName);
    // Initialization judgment
    if (!handle->isInitialized()) {
        rv = error::Code::NotInitializeErr;
        goto cleanup;
    }
    // Export private key
    rv = CY_SAF_InternalExportPrivateKey(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            1,
            &uiAlgorithm,
            pucPrivateKey,
            &uiPrivateKeyLen);
    if (rv != error::Code::Ok) {
        LOGM(ERROR, "ExportPrivateKey fail, file code: " << std::hex << rv);
        goto cleanup;
    }
    iKeyPair = std::make_shared<RsaKeyPair>();
    if (!iKeyPair) {
        rv = error::Code::UnknownErr;
        goto cleanup;
    }
    vPrivateKey.assign(pucPrivateKey, pucPrivateKey + uiPrivateKeyLen);
    if (!iKeyPair->ImportDerPrivateKey(vPrivateKey) &&
        !iKeyPair->ImportDerPublicKey(vPrivateKey)) {
        LOGM(ERROR, "ImportDerKey fail, file code: " << std::hex << rv);
        rv = error::Code::KeyEncodeErr;
        goto cleanup;
    }
    // Make Signature
    switch (uiHashAlgoType) {
        case SGD_NONE:   hashAlgorithm = "NONE";   break;
        case SGD_SHA1:   hashAlgorithm = "SHA1";   break;
        case SGD_SHA256: hashAlgorithm = "SHA256"; break;
        case SGD_SHA512: hashAlgorithm = "SHA512"; break;
        default: return error::Code::AlgoTypeErr;
    }
    FUNC_PARAMETER(hashAlgorithm);
    vMessage.assign(pucInData, pucInData + uiInDataLen);
    iSigner = std::make_shared<RsaSigner>();
    if (!iSigner) {
        rv = error::Code::UnknownErr;
        goto cleanup;
    }
    iSigner->SetRsaPadding(ISigner::PSS);
    if (!iSigner->MakeSignature(iKeyPair.get(), hashAlgorithm, vMessage, vSignature)) {
        rv = error::Code::SignErr;
        goto cleanup;
    }
    if (pucSignature == nullptr) {
        *puiSignatureLen = vSignature.size();
        rv = error::Code::Ok;
        goto cleanup;
    }
    if (*puiSignatureLen < vSignature.size()) {
        rv = error::Code::IndataLenErr;
        goto cleanup;
    }
    memcpy(pucSignature, vSignature.data(), vSignature.size());
    *puiSignatureLen = vSignature.size();
    rv = error::Code::Ok;
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_RsaSignFile(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiHashAlgoType,
        const char *pcFileName,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen)
{
    DCHECK_NUL(hAppHandle, pucContainerName, pcFileName, puiSignatureLen);
    unsigned char ucDigest[64] = {0};
    unsigned int  uiDigestLen = 64;
    FUNC_ENTRY;
    FUNC_PARAMETER(pcFileName);
    int rv = CY_SAF_HashFile(uiHashAlgoType, pcFileName, ucDigest, &uiDigestLen);
    if (rv != CYBER_R_SUCCESS) {
        goto cleanup;
    }
    FUNC_PARAMETER(HexUtils::EncodeStr(ucDigest, uiDigestLen));
    rv = CY_SAF_RsaSign(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiHashAlgoType,
            ucDigest,
            uiDigestLen,
            pucSignature,
            puiSignatureLen);
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_RsaSignFilePss(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiHashAlgoType,
        const char *pucFileName,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen)
{
    DCHECK_NUL(hAppHandle, pucContainerName, pucFileName, puiSignatureLen);
    unsigned char ucDigest[64] = {0};
    unsigned int  uiDigestLen = 64;
    FUNC_ENTRY;
    FUNC_PARAMETER(pucFileName);
    int rv = CY_SAF_HashFile(uiHashAlgoType, pucFileName, ucDigest, &uiDigestLen);
    if (rv != CYBER_R_SUCCESS) {
        goto cleanup;
    }
    FUNC_PARAMETER(HexUtils::EncodeStr(ucDigest, uiDigestLen));
    rv = CY_SAF_RsaSignPss(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiHashAlgoType,
            ucDigest,
            uiDigestLen,
            pucSignature,
            puiSignatureLen);
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_RsaVerifySign(
        unsigned int uiHashAlgoType,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen)
{
    DCHECK_NUL(pucPublicKey, pucInData, pucSignature);
    int rv = error::Code::Ok;
    std::string sAlgorithm;
    std::vector<unsigned char> vMessage, vSignature, vPublicKey;
    std::shared_ptr<IKeyPair> iKeyPair;
    std::shared_ptr<ISigner> iSigner;
    FUNC_ENTRY;
    // Hash Algorithm
    switch (uiHashAlgoType) {
        case SGD_NONE:   sAlgorithm = "NONE";   break;
        case SGD_SHA1:   sAlgorithm = "SHA1";   break;
        case SGD_SHA256: sAlgorithm = "SHA256"; break;
        case SGD_SHA512: sAlgorithm = "SHA512"; break;
        default: rv = error::Code::AlgoTypeErr; goto cleanup;
    }
    FUNC_PARAMETER(sAlgorithm);
    // Public Key
    vPublicKey.assign(pucPublicKey, pucPublicKey + uiPublicKeyLen);
    iKeyPair = AsymmetricKey::CreateKeyPair("RSA");
    if (iKeyPair == nullptr) {
        rv = error::Code::UnknownErr;
        goto cleanup;
    }
    if (!iKeyPair->ImportDerPublicKey(vPublicKey)) {
        rv = error::Code::KeyEncodeErr;
        goto cleanup;
    }
    // Verify Signature
    vMessage.assign(pucInData, pucInData + uiInDataLen);
    vSignature.assign(pucSignature, pucSignature + uiSignatureLen);
    iSigner = AsymmetricSigner::CreateSigner("RSA");
    if (iSigner == nullptr) {
        rv = error::Code::UnknownErr;
        goto cleanup;
    }
    if (!iSigner->VerifySignature(iKeyPair.get(), sAlgorithm, vMessage, vSignature)) {
        rv = error::Code::VerifyErr;
        goto cleanup;
    }
    rv = error::Code::Ok;
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_RsaVerifySignPss(
        unsigned int uiHashAlgoType,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen)
{
    DCHECK_NUL(pucPublicKey, pucInData, pucSignature);
    int rv = error::Code::Ok;
    std::string hashAlgorithm;
    std::vector<unsigned char> vMessageDigest, vSignature, vPublicKey;
    std::shared_ptr<IKeyPair> iKeyPair;
    std::shared_ptr<ISigner> iSigner;
    FUNC_ENTRY;
    // Hash Algorithm
    switch (uiHashAlgoType) {
        case SGD_NONE:   hashAlgorithm = "NONE";   break;
        case SGD_SHA1:   hashAlgorithm = "SHA1";   break;
        case SGD_SHA256: hashAlgorithm = "SHA256"; break;
        case SGD_SHA512: hashAlgorithm = "SHA512"; break;
        default: return error::Code::AlgoTypeErr;
    }
    FUNC_PARAMETER(hashAlgorithm);
    // Public Key
    vPublicKey.assign(pucPublicKey, pucPublicKey + uiPublicKeyLen);
    iKeyPair = AsymmetricKey::CreateKeyPair("RSA");
    if (iKeyPair == nullptr) {
        rv = error::Code::UnknownErr;
        goto cleanup;
    }
    if (!iKeyPair->ImportDerPublicKey(vPublicKey)) {
        rv = error::Code::KeyEncodeErr;
        goto cleanup;
    }
    // Verify Signature
    vMessageDigest.assign(pucInData, pucInData + uiInDataLen);
    vSignature.assign(pucSignature, pucSignature + uiSignatureLen);
    iSigner = AsymmetricSigner::CreateSigner("RSA");
    if (iSigner == nullptr) {
        rv = error::Code::UnknownErr;
        goto cleanup;
    }
    iSigner->SetRsaPadding(ISigner::PSS);
    if (!iSigner->VerifySignature(iKeyPair.get(), hashAlgorithm, vMessageDigest, vSignature)) {
        rv = error::Code::VerifyErr;
        goto cleanup;
    }
    rv = error::Code::Ok;
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_RsaVerifySignFile(
        unsigned int uiHashAlgoType,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        const char *pcFileName,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen)
{
    DCHECK_NUL(pucPublicKey, pcFileName, pucSignature);
    unsigned char ucDigest[64] = {0};
    unsigned int  uiDigestLen = 64;
    FUNC_ENTRY;
    FUNC_PARAMETER(uiHashAlgoType);
    FUNC_PARAMETER(pcFileName);
    int rv = CY_SAF_HashFile(uiHashAlgoType, pcFileName, ucDigest, &uiDigestLen);
    if (rv != CYBER_R_SUCCESS) {
        goto cleanup;
    }
    FUNC_PARAMETER(HexUtils::EncodeStr(ucDigest, uiDigestLen));
    rv = CY_SAF_RsaVerifySign(
            uiHashAlgoType,
            pucPublicKey,
            uiPublicKeyLen,
            ucDigest,
            uiDigestLen,
            pucSignature,
            uiSignatureLen);
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_RsaVerifySignFilePss(
        unsigned int uiHashAlgoType,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        const char *pcFileName,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen)
{
    DCHECK_NUL(pucPublicKey, pcFileName, pucSignature);
    unsigned char ucDigest[64] = {0};
    unsigned int  uiDigestLen = 64;
    FUNC_ENTRY;
    FUNC_PARAMETER(pcFileName);
    int rv = CY_SAF_HashFile(uiHashAlgoType, pcFileName, ucDigest, &uiDigestLen);
    if (rv != CYBER_R_SUCCESS) {
        goto cleanup;
    }
    FUNC_PARAMETER(HexUtils::EncodeStr(ucDigest, uiDigestLen));
    rv = CY_SAF_RsaVerifySignPss(
            uiHashAlgoType,
            pucPublicKey,
            uiPublicKeyLen,
            ucDigest,
            uiDigestLen,
            pucSignature,
            uiSignatureLen);
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_RsaVerifySignByCert(
        unsigned int uiHashAlgoType,
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen)
{
    DCHECK_NUL(pucCertificate, pucInData, pucSignature);
    unsigned char ucPublicKey[2048] = { 0 };
    unsigned int  uiPublicKeyLen = 2048;
    FUNC_ENTRY;
    int rv = CY_SAF_GetCertificateInfo(
            pucCertificate,
            uiCertificateLen,
            SGD_CERT_DER_PUBLIC_KEY,
            ucPublicKey,
            &uiPublicKeyLen);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    rv = CY_SAF_RsaVerifySign(
            uiHashAlgoType,
            ucPublicKey,
            uiPublicKeyLen,
            pucInData,
            uiInDataLen,
            pucSignature,
            uiSignatureLen);
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_RsaVerifySignByCertPss(
        unsigned int uiHashAlgoType,
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen)
{
    DCHECK_NUL(pucCertificate, pucInData, pucSignature);
    unsigned char ucPublicKey[2048] = { 0 };
    unsigned int  uiPublicKeyLen = 2048;
    FUNC_ENTRY;
    int rv = CY_SAF_GetCertificateInfo(
            pucCertificate,
            uiCertificateLen,
            SGD_CERT_DER_PUBLIC_KEY,
            ucPublicKey,
            &uiPublicKeyLen);
    if (rv != error::Code::Ok) {
        LOGM(ERROR, "GetCertificateInfo fail, fail code: " << std::hex << rv);
        goto cleanup;
    }
    rv = CY_SAF_RsaVerifySignPss(
            uiHashAlgoType,
            ucPublicKey,
            uiPublicKeyLen,
            pucInData,
            uiInDataLen,
            pucSignature,
            uiSignatureLen);
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_RsaVerifySignFileByCert(
        unsigned int uiHashAlgoType,
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        const char *pcFileName,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen)
{
    DCHECK_NUL(pucCertificate, pcFileName, pucSignature);
    unsigned char ucPublicKey[2048] = { 0 };
    unsigned int  uiPublicKeyLen = 2048;
    unsigned int keyUsage = 0;
    FUNC_ENTRY;
    FUNC_PARAMETER(pcFileName);
    // Verify Certificate Key usage
    int rv = CY_SAF_GetCertificateKeyUsage(pucCertificate, uiCertificateLen, &keyUsage);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    // The certificate does not have the signature verification function
    if (((keyUsage & (1 << 3)) != (1 << 3))) {
        FUNC_PARAMETER(keyUsage);
        rv = error::Code::KeyUsageErr;
        goto cleanup;
    }
    // Export Certificate PublicKey
    rv = CY_SAF_GetCertificateInfo(
            pucCertificate,
            uiCertificateLen,
            SGD_CERT_DER_PUBLIC_KEY,
            ucPublicKey,
            &uiPublicKeyLen);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    rv = CY_SAF_RsaVerifySignFile(
            uiHashAlgoType,
            ucPublicKey,
            uiPublicKeyLen,
            pcFileName,
            pucSignature,
            uiSignatureLen);
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_RsaVerifySignFileByCertPss(
        unsigned int uiHashAlgoType,
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        const char *pcFileName,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen)
{
    DCHECK_NUL(pucCertificate, pcFileName, pucSignature);
    unsigned char ucPublicKey[2048] = { 0 };
    unsigned int  uiPublicKeyLen = 2048;
    unsigned int keyUsage = 0;
    FUNC_ENTRY;
    FUNC_PARAMETER(pcFileName);
    // Verify Certificate Key usage
    int rv = CY_SAF_GetCertificateKeyUsage(pucCertificate, uiCertificateLen, &keyUsage);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    // The certificate does not have the signature verification function
    if (((keyUsage & (1 << 3)) != (1 << 3))) {
        FUNC_PARAMETER(keyUsage);
        rv = error::Code::KeyUsageErr;
        goto cleanup;
    }
    // Export Certificate PublicKey
    rv = CY_SAF_GetCertificateInfo(
            pucCertificate,
            uiCertificateLen,
            SGD_CERT_DER_PUBLIC_KEY,
            ucPublicKey,
            &uiPublicKeyLen);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    rv = CY_SAF_RsaVerifySignFilePss(
            uiHashAlgoType,
            ucPublicKey,
            uiPublicKeyLen,
            pcFileName,
            pucSignature,
            uiSignatureLen);
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_RsaEncrypt(
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int  *puiDataLen)
{
    DCHECK_NUL(pucPublicKey, pucInData, puiDataLen);
    int rv = error::Code::Ok;
    std::vector<unsigned char> vPlainData, vCipherData, vPublicKey;
    std::shared_ptr<IKeyPair> iKeyPair;
    std::shared_ptr<IEncipher> iEncipher;
    FUNC_ENTRY;
    FUNC_PARAMETER(uiInDataLen);
    // Public Key
    vPublicKey.assign(pucPublicKey, pucPublicKey + uiPublicKeyLen);
    iKeyPair = AsymmetricKey::CreateKeyPair("RSA");
    if (iKeyPair == nullptr) {
        rv = error::Code::UnknownErr;
        goto cleanup;
    }
    if (!iKeyPair->ImportDerPublicKey(vPublicKey)) {
        rv = error::Code::KeyEncodeErr;
        goto cleanup;
    }
    // Encrypt Data
    vPlainData.assign(pucInData, pucInData + uiInDataLen);
    iEncipher = AsymmetricEncipher::CreateEncipher("RSA");
    if (iEncipher == nullptr) {
        rv = error::Code::UnknownErr;
        goto cleanup;
    }
    if (!iEncipher->EncryptData(iKeyPair.get(), vPlainData, vCipherData)) {
        rv = error::Code::EncErr;
        goto cleanup;
    }
    if (pucData == nullptr) {
        *puiDataLen = vCipherData.size();
        goto cleanup;
    }
    if (*puiDataLen < vCipherData.size()) {
        rv = error::Code::IndataLenErr;
        goto cleanup;
    }
    memcpy(pucData, vCipherData.data(), vCipherData.size());
    *puiDataLen = vCipherData.size();
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_RsaEncryptByCert(
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int *uiDataLen)
{
    DCHECK_NUL(pucCertificate, pucInData, pucData);
    int rv;
    unsigned char ucPublicKey[2048] = { 0 };
    unsigned int  uiPublicKeyLen = 2048;
    FUNC_ENTRY;
    FUNC_PARAMETER(uiInDataLen);
    rv = CY_SAF_GetCertificateInfo(
            pucCertificate,
            uiCertificateLen,
            SGD_CERT_DER_PUBLIC_KEY,
            ucPublicKey,
            &uiPublicKeyLen);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    rv = CY_SAF_RsaEncrypt(
            ucPublicKey,
            uiPublicKeyLen,
            pucInData,
            uiInDataLen,
            pucData,
            uiDataLen);
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_RsaDecrypt(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int *puiDataLen)
{
    DCHECK_NUL(hAppHandle, pucContainerName, pucInData, pucData);
    int rv;
    unsigned char pucPrivateKey[3072] = {0};
    unsigned int uiPrivateKeyLen = 3072;
    unsigned int uiAlgorithm = 0;
    std::vector<unsigned char> vPrivateKey, vCipherData, vPlainData;
    auto *handler = static_cast<Handler *>(hAppHandle);
    std::shared_ptr<IKeyPair> iKeyPair;
    std::shared_ptr<IEncipher> iEncipher;
    FUNC_ENTRY;
    FUNC_PARAMETER(hAppHandle);
    FUNC_PARAMETER(pucContainerName);
    FUNC_PARAMETER(uiInDataLen);
    // Initialization judgment
    if (!handler->isInitialized()) {
        rv = error::Code::NotInitializeErr;
        goto cleanup;
    }
    // Export private key
    rv = CY_SAF_InternalExportPrivateKey(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            1,
            &uiAlgorithm,
            pucPrivateKey,
            &uiPrivateKeyLen);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    iKeyPair = std::make_shared<RsaKeyPair>();
    if (!iKeyPair) {
        rv = error::Code::UnknownErr;
        goto cleanup;
    }
    vPrivateKey.assign(pucPrivateKey, pucPrivateKey + uiPrivateKeyLen);
    if (!iKeyPair->ImportDerPrivateKey(vPrivateKey) &&
        !iKeyPair->ImportDerPublicKey(vPrivateKey)) {
        rv = error::Code::KeyEncodeErr;
        goto cleanup;
    }
    // DecryptData
    vCipherData.assign(pucInData, pucInData + uiInDataLen);
    iEncipher = AsymmetricEncipher::CreateEncipher("RSA");
    if (!iEncipher->DecryptData(iKeyPair.get(), vCipherData, vPlainData)) {
        rv = error::Code::DecErr;
        goto cleanup;
    }
    if (pucData == nullptr) {
        *puiDataLen = vPlainData.size();
        goto cleanup;
    }
    if (*puiDataLen < vPlainData.size()) {
        rv = error::Code::IndataErr;
        goto cleanup;
    }
    memcpy(pucData, vPlainData.data(), vPlainData.size());
    *puiDataLen = vPlainData.size();
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_GenEccKeyPair(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiAlgorithmID,
        unsigned int uiKeyUsage,
        unsigned int uiExportFlag)
{
    DCHECK_NUL(hAppHandle, pucContainerName);
    int rv = -1;
    auto *handler = static_cast<Handler *>(hAppHandle);
    std::shared_ptr<IKeyPair> iKeyPair;
    std::vector<unsigned char> vBuffer;
    std::string sAlgorithm = "ECC", sContainerPin;
    FUNC_ENTRY;
    FUNC_PARAMETER(hAppHandle);
    FUNC_PARAMETER(pucContainerName);
    FUNC_PARAMETER(uiAlgorithmID);
    FUNC_PARAMETER(uiKeyUsage);
    // Initialization judgment
    if (!handler->isInitialized()) {
        rv = error::Code::NotInitializeErr;
        goto cleanup;
    }
    if (uiAlgorithmID != SGD_ECC &&
        uiAlgorithmID != SGD_BRAINPOOL_P256R1 &&
        uiAlgorithmID != SGD_SM2) {
        rv = error::Code::AlgoTypeErr;
        goto cleanup;
    }
    // Generate KeyPair
    switch (uiAlgorithmID) {
        case SGD_ECC:
            sAlgorithm = "ECC";
            break;
        case SGD_BRAINPOOL_P256R1:
            sAlgorithm = "BRAINPOOL_P256R1";
            break;
        case SGD_SM2:
            sAlgorithm = "SM2";
            break;
        default:
            break;
    }
    FUNC_PARAMETER(sAlgorithm);
    iKeyPair = AsymmetricKey::CreateKeyPair(sAlgorithm);
    if (iKeyPair == nullptr) {
        rv = error::Code::KeyInfoTypeErr;
        goto cleanup;
    }
    if (!iKeyPair->GenerateKeyPair(256, sAlgorithm)) {
        rv = error::Code::GenKeyErr;
        goto cleanup;
    }
    // Storage PublicKey
    if (!iKeyPair->ExportDerPublicKey(vBuffer)) {
        rv = error::Code::KeyEncodeErr;
        goto cleanup;
    }
    rv = CY_SAF_ImportEccPublicKey(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiAlgorithmID,
            uiKeyUsage,
            vBuffer.data(),
            vBuffer.size());
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    // If a security chip is used, the public key is stored locally
    if (!handler->isHardWare()) {
        iKeyPair->ExportDerPrivateKey(vBuffer);
    }
    rv = CY_SAF_ImportEccPrivateKey(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiAlgorithmID,
            uiKeyUsage,
            vBuffer.data(),
            vBuffer.size());
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_ImportEccPublicKey(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiAlgorithm,
        unsigned int uiKeyUsage,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen)
{
    DCHECK_NUL(hAppHandle, pucContainerName, pucPublicKey);
    int rv = error::Code::Ok;
    std::unique_ptr<Container> cContainer(new Container);
    std::string sContainerName(reinterpret_cast<const char *>(pucContainerName),
                               uiContainerNameLen);
    std::vector<unsigned char> vData;
    Container::Usage usage;
    Container::Algorithm algorithm;
    unsigned int uiContainerType;
    if (uiKeyUsage == SGD_KEYUSAGE_SIGN) {
        uiContainerType = SIGN_PUB_KEY;
        usage = Container::SIGN;
    } else if (uiKeyUsage == SGD_KEYUSAGE_ENC) {
        uiContainerType = ENC_PUB_KEY;
        usage = Container::ENC;
    } else {
        return error::Code::KeyUsageErr;
    }
    switch (uiAlgorithm) {
        case SGD_RSA:     algorithm = Container::RSA;     break;
        case SGD_SM2:     algorithm = Container::SM2;     break;
        case SGD_ECC:     algorithm = Container::ECC;     break;
        case SGD_BRAINPOOL_P256R1: algorithm = Container::BRAINPOOL_P256R1; break;
        default:          algorithm = Container::NONE;    break;
    }
    vData.assign(pucPublicKey, pucPublicKey + uiPublicKeyLen);
    cContainer = ContainerBuilder()
            .SetStorageType(Container::PUBLIC_KEY)
            .SetContainerName(sContainerName)
            .SetUsage(usage)
            .SetAlgorithm(algorithm)
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
            uiContainerType,
            vData.data(),
            vData.size());
    return rv;
}

int CY_SAF_ImportEccPrivateKey(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiAlgorithm,
        unsigned int uiKeyUsage,
        unsigned char *pucPrivateKey,
        unsigned int uiPrivateKeyLen)
{
    DCHECK_NUL(hAppHandle, pucContainerName, pucPrivateKey);
    int rv = 0;
    Container::Usage usage;
    Container::Algorithm algorithm;
    unsigned int uiContainerType;
    auto *handler = static_cast<Handler *>(hAppHandle);
    std::unique_ptr<Container> cContainer(new Container);
    std::string sContainerName;
    std::string sContainerPin;
    std::vector<unsigned char> vData;
    if (uiKeyUsage == SGD_KEYUSAGE_SIGN) {
        uiContainerType = SIGN_KEY;
        usage = Container::SIGN;
    } else if (uiKeyUsage == SGD_KEYUSAGE_ENC) {
        uiContainerType = ENC_KEY;
        usage = Container::ENC;
    } else {
        return error::Code::KeyUsageErr;
    }
    switch (uiAlgorithm) {
        case SGD_RSA:     algorithm = Container::RSA;     break;
        case SGD_SM2:     algorithm = Container::SM2;     break;
        case SGD_ECC:     algorithm = Container::ECC;     break;
        case SGD_BRAINPOOL_P256R1: algorithm = Container::BRAINPOOL_P256R1; break;
        default:          algorithm = Container::NONE;    break;
    }
    sContainerName.assign((const char *)pucContainerName, uiContainerNameLen);
    sContainerPin.assign((const char *)handler->GetContainerPin().c_str(),
                         handler->GetContainerPin().size());
    vData.assign(pucPrivateKey, pucPrivateKey + uiPrivateKeyLen);
    cContainer = ContainerBuilder()
            .SetStorageType(Container::PRIVATE_KEY)
            .SetContainerName(sContainerName)
            .SetUsage(usage)
            .SetAlgorithm(algorithm)
            .SetContainerPin(sContainerPin)
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
            uiContainerType,
            vData.data(),
            vData.size());
    return rv;
}

int CY_SAF_GetEccPublicKey(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiKeyUsage,
        unsigned char *pucPublicKey,
        unsigned int *uiPublicKeyLen)
{
    DCHECK_NUL(hAppHandle, pucContainerName, pucPublicKey);
    int rv;
    unsigned int uiContainerType;
    auto *handler = static_cast<Handler *>(hAppHandle);
    FUNC_ENTRY;
    FUNC_PARAMETER(pucContainerName);
    FUNC_PARAMETER(uiKeyUsage);
    // Initialization judgment
    if (!handler->isInitialized()) {
        rv = error::Code::NotInitializeErr;
        goto cleanup;
    }
    switch (uiKeyUsage) {
        case SGD_KEYUSAGE_SIGN:  uiContainerType = SIGN_PUB_KEY; break;
        case SGD_KEYUSAGE_ENC:   uiContainerType = ENC_PUB_KEY;  break;
        default: rv = error::Code::KeyUsageErr; goto cleanup;
    }
    
    rv = CY_SAF_InternalReadContainer(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiContainerType,
            nullptr,
            0,
            nullptr,
            pucPublicKey,
            uiPublicKeyLen);
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_EccSign(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiHashAlgoType,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen)
{
    DCHECK_NUL(hAppHandle, pucContainerName, pucInData, puiSignatureLen);
    int rv;
    unsigned char ucPrivateKey[2048] = {0};
    unsigned int uiPrivateKeyLen = 2048;
    unsigned int uiAlgorithm = 0;
    std::vector<unsigned char> vPrivateKey, vMessage, vSignature;
    auto *handler = static_cast<Handler *>(hAppHandle);
    std::shared_ptr<IKeyPair> iKeyPair;
    std::shared_ptr<ISigner> iSigner;
    std::string hashAlgorithm;
    FUNC_ENTRY;
    FUNC_PARAMETER(hAppHandle);
    FUNC_PARAMETER(pucContainerName);
    // Initialization judgment
    if (!handler->isInitialized()) {
        rv = error::Code::NotInitializeErr;
        goto cleanup;
    }
    // Export private key
    rv = CY_SAF_InternalExportPrivateKey(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            1,
            &uiAlgorithm,
            ucPrivateKey,
            &uiPrivateKeyLen);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    vPrivateKey.assign(ucPrivateKey, ucPrivateKey + uiPrivateKeyLen);
    iKeyPair = std::make_shared<EccKeyPair>();
    if (!iKeyPair) {
        rv = error::Code::UnknownErr;
        goto cleanup;
    }
    if (!iKeyPair->ImportDerPrivateKey(vPrivateKey) &&
        !iKeyPair->ImportDerPublicKey(vPrivateKey)) {
        rv = error::Code::KeyEncodeErr;
        goto cleanup;
    }
    // Make Signature
    switch (uiHashAlgoType) {
        case SGD_NONE:   hashAlgorithm = "NONE";   break;
        case SGD_SHA1:   hashAlgorithm = "SHA1";   break;
        case SGD_SHA256: hashAlgorithm = "SHA256"; break;
        case SGD_SHA512: hashAlgorithm = "SHA512"; break;
        case SGD_SM3:    hashAlgorithm = "SM3";    break;
        default: rv = error::Code::AlgoTypeErr; goto cleanup;
    }
    FUNC_PARAMETER(hashAlgorithm);
    iSigner = AsymmetricSigner::CreateSigner(iKeyPair->GetAlgorithmName());
    if (!iSigner) {
        rv = error::Code::UnknownErr;
        goto cleanup;
    }
    vMessage.assign(pucInData, pucInData + uiInDataLen);
    if (!iSigner->MakeSignature(iKeyPair.get(), hashAlgorithm, vMessage, vSignature)) {
        rv = error::Code::SignErr;
        goto cleanup;
    }
    if (pucSignature == nullptr) {
        *puiSignatureLen = vSignature.size();
        rv = error::Code::Ok;
        goto cleanup;
    }
    if (*puiSignatureLen < vSignature.size()) {
        rv = error::Code::IndataLenErr;
        goto cleanup;
    }
    memcpy(pucSignature, vSignature.data(), vSignature.size());
    *puiSignatureLen = vSignature.size();
    rv = error::Code::Ok;
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_EccSignFile(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiHashAlgoType,
        const char *pcFileName,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen)
{
    DCHECK_NUL(hAppHandle, pucContainerName, pcFileName, puiSignatureLen);
    unsigned char ucDigest[64] = {0};
    unsigned int uiDigestLen   = 64;
    FUNC_ENTRY;
    FUNC_PARAMETER(pucContainerName);
    FUNC_PARAMETER(uiHashAlgoType);
    FUNC_PARAMETER(pcFileName);
    int rv = CY_SAF_HashFile(uiHashAlgoType, pcFileName, ucDigest, &uiDigestLen);
    if (rv != CYBER_R_SUCCESS) {
        goto cleanup;
    }
    FUNC_PARAMETER(HexUtils::EncodeStr(ucDigest, uiDigestLen));
    rv = CY_SAF_EccSign(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiHashAlgoType,
            ucDigest,
            uiDigestLen,
            pucSignature,
            puiSignatureLen);
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_EccVerifySign(
        unsigned int uiHashAlgoType,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen)
{
    DCHECK_NUL(pucPublicKey, pucInData, pucSignature);
    int rv = error::Code::Ok;
    std::string hashAlgorithm;
    std::vector<unsigned char> vPublicKey, vMessage, vSignature;
    std::shared_ptr<IKeyPair> iKeyPair;
    std::shared_ptr<ISigner> iSigner;
    FUNC_ENTRY;
    // Hash Algorithm
    switch (uiHashAlgoType) {
        case SGD_NONE:   hashAlgorithm = "NONE";   break;
        case SGD_SHA1:   hashAlgorithm = "SHA1";   break;
        case SGD_SHA256: hashAlgorithm = "SHA256"; break;
        case SGD_SHA512: hashAlgorithm = "SHA512"; break;
        case SGD_SM3:    hashAlgorithm = "SM3";    break;
        default: rv = error::Code::AlgoTypeErr;    goto cleanup;
    }
    FUNC_PARAMETER(hashAlgorithm);
    // Public Key
    vPublicKey.assign(pucPublicKey, pucPublicKey + uiPublicKeyLen);
    FUNC_PARAMETER(HexUtils::EncodeStr(pucPublicKey, uiPublicKeyLen));
    iKeyPair = AsymmetricKey::CreateKeyPair("ECC");
    if (iKeyPair == nullptr || !iKeyPair->ImportDerPublicKey(vPublicKey)) {
        rv = error::Code::KeyEncodeErr;
        goto cleanup;
    }
    // Verify Signature
    vMessage.assign(pucInData, pucInData + uiInDataLen);
    vSignature.assign(pucSignature, pucSignature + uiSignatureLen);
    FUNC_PARAMETER(iKeyPair->GetAlgorithmName());
    iSigner = AsymmetricSigner::CreateSigner(iKeyPair->GetAlgorithmName());
    if (iSigner == nullptr) {
        rv = error::Code::UnknownErr;
        goto cleanup;
    }
    if (!iSigner->VerifySignature(iKeyPair.get(), hashAlgorithm, vMessage, vSignature)) {
        rv = error::Code::VerifyErr;
        goto cleanup;
    }
    rv = error::Code::Ok;
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_EccVerifySignFile(
        unsigned int uiHashAlgoType,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        const char *pcFileName,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen)
{
    DCHECK_NUL(pucPublicKey, pcFileName, pucSignature);
    unsigned char ucDigest[64] = {0};
    unsigned int uiDigestLen   = 64;
    FUNC_ENTRY;
    FUNC_PARAMETER(pcFileName);
    int rv = CY_SAF_HashFile(uiHashAlgoType, pcFileName, ucDigest, &uiDigestLen);
    if (rv != CYBER_R_SUCCESS) {
        goto cleanup;
    }
    FUNC_PARAMETER(HexUtils::EncodeStr(ucDigest, uiDigestLen));
    rv = CY_SAF_EccVerifySign(
            uiHashAlgoType,
            pucPublicKey,
            uiPublicKeyLen,
            ucDigest,
            uiDigestLen,
            pucSignature,
            uiSignatureLen);
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_EccEncrypt(
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int  *puiDataLen)
{
    DCHECK_NUL(pucPublicKey, pucInData, puiDataLen);
    int rv = error::Code::Ok;
    std::vector<unsigned char> vPlainData, vCipherData, vPublicKey;
    std::shared_ptr<IKeyPair> iKeyPair;
    std::shared_ptr<IEncipher> iEncipher;
    FUNC_ENTRY;
    FUNC_PARAMETER(HexUtils::EncodeStr(pucPublicKey, uiPublicKeyLen));
    // Public Key
    iKeyPair = AsymmetricKey::CreateKeyPair("ECC");
    if (iKeyPair == nullptr) {
        rv = error::Code::MemoryErr;
        goto cleanup;
    }
    // Public Key
    vPublicKey.assign(pucPublicKey, pucPublicKey + uiPublicKeyLen);
    if (!iKeyPair->ImportDerPublicKey(vPublicKey)) {
        rv = error::Code::KeyEncodeErr;
        goto cleanup;
    }
    // Encrypt Data
    vPlainData.assign(pucInData, pucInData + uiInDataLen);
    FUNC_PARAMETER(iKeyPair->GetAlgorithmName());
    iEncipher = AsymmetricEncipher::CreateEncipher(iKeyPair->GetAlgorithmName());
    if (iEncipher == nullptr) {
        rv = error::Code::AlgoTypeErr;
        goto cleanup;
    }
    if (!iEncipher->EncryptData(iKeyPair.get(), vPlainData, vCipherData)) {
        rv = error::Code::EncErr;
        goto cleanup;
    }
    if (pucData == nullptr) {
        *puiDataLen = vCipherData.size();
        goto cleanup;
    }
    if (*puiDataLen < vCipherData.size()) {
        rv = error::Code::IndataLenErr;
        goto cleanup;
    }
    memcpy(pucData, vCipherData.data(), vCipherData.size());
    *puiDataLen = vCipherData.size();
    rv = error::Code::Ok;
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_EccEncryptByCert(
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int *uiDataLen)
{
    DCHECK_NUL(pucCertificate, pucInData, pucData);
    int rv = error::Code::Ok;
    unsigned char ucPublicKey[2048] = { 0 };
    unsigned int  uiPublicKeyLen = 2048;
    FUNC_ENTRY;
    FUNC_PARAMETER(uiInDataLen);
    rv = CY_SAF_GetCertificateInfo(
            pucCertificate,
            uiCertificateLen,
            SGD_CERT_DER_PUBLIC_KEY,
            ucPublicKey,
            &uiPublicKeyLen);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    rv = CY_SAF_EccEncrypt(
            ucPublicKey,
            uiPublicKeyLen,
            pucInData,
            uiInDataLen,
            pucData,
            uiDataLen);
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_EccDecrypt(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int *puiDataLen)
{
    DCHECK_NUL(hAppHandle, pucContainerName, pucInData, pucData);
    int rv;
    unsigned char pucPrivateKey[2048] = {0};
    unsigned int uiPrivateKeyLen = 2048;
    unsigned int uiAlgorithm = 0;
    std::vector<unsigned char> vPrivateKey, vCipherData, vPlainData;
    auto *handler = static_cast<Handler *>(hAppHandle);
    std::shared_ptr<IKeyPair> iKeyPair;
    std::shared_ptr<IEncipher> iEncipher;
    FUNC_ENTRY;
    FUNC_PARAMETER(hAppHandle);
    FUNC_PARAMETER(pucContainerName);
    FUNC_PARAMETER(uiInDataLen);
    // Initialization judgment
    if (!handler->isInitialized()) {
        rv = error::Code::NotInitializeErr;
        goto cleanup;
    }
    // Export private key
    rv = CY_SAF_InternalExportPrivateKey(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            1,
            &uiAlgorithm,
            pucPrivateKey,
            &uiPrivateKeyLen);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    iKeyPair = std::make_shared<EccKeyPair>();
    if (!iKeyPair) {
        rv = error::Code::UnknownErr;
        goto cleanup;
    }
    vPrivateKey.assign(pucPrivateKey, pucPrivateKey + uiPrivateKeyLen);
    if (!iKeyPair->ImportDerPrivateKey(vPrivateKey) &&
        !iKeyPair->ImportDerPublicKey(vPrivateKey)) {
        rv = error::Code::KeyEncodeErr;
        goto cleanup;
    }
    // DecryptData
    vCipherData.assign(pucInData, pucInData + uiInDataLen);
    FUNC_PARAMETER(iKeyPair->GetAlgorithmName());
    iEncipher = AsymmetricEncipher::CreateEncipher(iKeyPair->GetAlgorithmName());
    if (iEncipher == nullptr) {
        rv = error::Code::AlgoTypeErr;
        goto cleanup;
    }
    if (!iEncipher->DecryptData(iKeyPair.get(), vCipherData, vPlainData)) {
        rv = error::Code::DecErr;
        goto cleanup;
    }
    if (pucData == nullptr) {
        *puiDataLen = vPlainData.size();
        goto cleanup;
    }

    if (*puiDataLen < vPlainData.size()) {
        rv = error::Code::IndataErr;
        goto cleanup;
    }
    memcpy(pucData, vPlainData.data(), vPlainData.size());
    *puiDataLen = vPlainData.size();
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_Sm2DecryptKeyBlob(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int *puiDataLen)
{
    DCHECK_NUL(hAppHandle, pucContainerName, pucInData, pucData, puiDataLen);
    int rv;
    unsigned char pucPrivateKey[2048] = {0};
    unsigned int uiPrivateKeyLen = 2048;
    unsigned int uiAlgorithm = 0;
    std::vector<unsigned char> vPrivateKey, vCipherData, vPlainData;
    auto *handler = static_cast<Handler *>(hAppHandle);
    std::shared_ptr<IKeyPair> iKeyPair;
    std::shared_ptr<Sm2Enveloper> iSm2Enveloper;
    FUNC_ENTRY;
    FUNC_PARAMETER(hAppHandle);
    FUNC_PARAMETER(pucContainerName);
    FUNC_PARAMETER(uiInDataLen);
    // Initialization judgment
    if (!handler->isInitialized()) {
        rv = error::Code::NotInitializeErr;
        goto cleanup;
    }
    // Export private key
    rv = CY_SAF_InternalExportPrivateKey(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            1,
            &uiAlgorithm,
            pucPrivateKey,
            &uiPrivateKeyLen);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    iKeyPair = std::make_shared<EccKeyPair>();
    if (!iKeyPair) {
        rv = error::Code::UnknownErr;
        goto cleanup;
    }
    vPrivateKey.assign(pucPrivateKey, pucPrivateKey + uiPrivateKeyLen);
    if (!iKeyPair->ImportDerPrivateKey(vPrivateKey) &&
        !iKeyPair->ImportDerPublicKey(vPrivateKey)) {
        rv = error::Code::KeyEncodeErr;
        goto cleanup;
    }
    // DecryptData
    vCipherData.assign(pucInData, pucInData + uiInDataLen);
    iSm2Enveloper = std::make_shared<Sm2Enveloper>();
    if (iSm2Enveloper == nullptr) {
        rv = error::Code::MemoryErr;
        goto cleanup;
    }
    if (!iSm2Enveloper->DecryptEnveloped(iKeyPair.get(),
                                         vCipherData, vPlainData)) {
        rv = error::Code::DecErr;
        goto cleanup;
    }
    if (*puiDataLen < vPlainData.size()) {
        rv = error::Code::IndataErr;
        goto cleanup;
    }
    iKeyPair->ImportRawPrivateKey("SM2", vPlainData);
    iKeyPair->ExportDerPrivateKey(vPlainData);
    memcpy(pucData, vPlainData.data(), vPlainData.size());
    *puiDataLen = vPlainData.size();
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_EccVerifySignByCert(
        unsigned int uiHashAlgoType,
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen)
{
    unsigned char ucPublicKey[2048] = { 0 };
    unsigned int  uiPublicKeyLen = 2048;
    FUNC_ENTRY;
    int rv = CY_SAF_GetCertificateInfo(
            pucCertificate,
            uiCertificateLen,
            SGD_CERT_DER_PUBLIC_KEY,
            ucPublicKey,
            &uiPublicKeyLen);
    if (rv != error::Code::Ok) {
        goto cleanup;
    }
    rv = CY_SAF_EccVerifySign(
            uiHashAlgoType,
            ucPublicKey,
            uiPublicKeyLen,
            pucInData,
            uiInDataLen,
            pucSignature,
            uiSignatureLen);
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_CreateSymmKeyObj(
        void **phSymmKeyObj,
        unsigned char *pucKey,
        unsigned int  uiKeyLen,
        unsigned char *pucIV,
        unsigned int  uiIVLen,
        unsigned int  uiEncOrDec,
        unsigned int  uiCryptoAlgID)
{
    std::string sAlgorithm;
    ISymm *iSymm = nullptr;
    ISymm::Mode mode;
    bool padding = false;
    DCHECK_NUL(pucKey);
    switch (uiCryptoAlgID) {
        case SGD_AES_ECB:
            sAlgorithm = "AES";
            mode = ISymm::ECB;
            padding = true;
            break;
        case SGD_AES_CBC:
            sAlgorithm = "AES";
            mode = ISymm::CBC;
            padding = true;
            break;
        case SGD_AES_CFB:
            sAlgorithm = "AES";
            mode = ISymm::CFB;
            break;
        case SGD_AES_OFB:
            sAlgorithm = "AES";
            mode = ISymm::OFB;
            break;
        case SGD_SM4_ECB:
            sAlgorithm = "SM4";
            mode = ISymm::ECB;
            padding = true;
            break;
        case SGD_SM4_CBC:
            sAlgorithm = "SM4";
            mode = ISymm::CBC;
            padding = true;
            break;
        case SGD_SM4_CFB:
            sAlgorithm = "SM4";
            mode = ISymm::CFB;
            break;
        case SGD_SM4_OFB:
            sAlgorithm = "SM4";
            mode = ISymm::OFB;
            break;
        case SGD_ZUC:
            sAlgorithm = "ZUC";
            mode = ISymm::NONE;
            break;
        default:
            return error::Code::AlgoTypeErr;
    }
    iSymm = Symmetric::CreateSymm(sAlgorithm);
    if (iSymm == nullptr) {
        return error::Code::AlgoTypeErr;
    }
    if (!iSymm->Init(mode, pucKey, uiKeyLen, pucIV, uiIVLen, uiEncOrDec, padding)) {
        return error::Code::IndataErr;
    }
    *phSymmKeyObj = iSymm;
    return error::Code::Ok;
}

int CY_SAF_GenerateKeyWithEPK(
        void *hSymmKeyObj,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        unsigned char *pucSymmKey,
        unsigned int *puiSymmKeyLen,
        void **phKeyHandle)
{
    return error::Code::NotSupportYetErr;
}

int CY_SAF_ImportEncryptedKey(
        void *hSymmKeyObj,
        unsigned char *pucSymmKey,
        unsigned int uiSymmKeyLen,
        void **phKeyHandle)
{
    return error::Code::NotSupportYetErr;
}

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
        void **phAgreementHandle)
{
    return error::Code::NotSupportYetErr;
}

int CY_SAF_GenerateKeyWithECC(
        void *phAgreementHandle,
        unsigned char *pucResponseID,
        unsigned int uiResponseIDLength,
        unsigned char *pucResponsePublicKey,
        unsigned int uiResponsePublicKeyLen,
        unsigned char *pucResponseTmpPublicKey,
        unsigned int uiResponseTmpPublicKeyLen,
        void **phKeyHandle)
{
    return error::Code::NotSupportYetErr;
}

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
        void **phKeyHandle)
{
    return error::Code::NotSupportYetErr;
}

int CY_SAF_DestroySymmAlgoObj(
        void *hSymmKeyObj)
{
    DCHECK_NUL(hSymmKeyObj);
    delete (ISymm *)hSymmKeyObj;
    return error::Code::Ok;
}

int CY_SAF_SymmEncrypt(
        void *hSymmKeyObj,
        const unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen)
{
    DCHECK_NUL(hSymmKeyObj, pucInData, puiOutDataLen);
    auto *encryptor = (ISymm *)hSymmKeyObj;
    std::vector<unsigned char> vInData;
    std::vector<unsigned char> vOutData1;
    vInData.assign(pucInData, pucInData + uiInDataLen);
    encryptor->Update(vInData, vOutData1);
    std::vector<unsigned char> vOutData2;
    encryptor->Final(vOutData2);
    if (pucOutData == nullptr) {
        *puiOutDataLen = vOutData1.size() + vOutData2.size();
        return error::Code::Ok;
    }
    if (*puiOutDataLen < vOutData1.size() + vOutData2.size()) {
        return error::Code::IndataLenErr;
    }
    memcpy(pucOutData, vOutData1.data(), vOutData1.size());
    memcpy(pucOutData + vOutData1.size(), vOutData2.data(), vOutData2.size());
    *puiOutDataLen = vOutData1.size() + vOutData2.size();
    return error::Code::Ok;
}

int CY_SAF_SymmEncryptUpdate(
        void *hSymmKeyObj,
        const unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen)
{
    DCHECK_NUL(hSymmKeyObj, pucInData, pucOutData, puiOutDataLen);
    auto *encryptor = (ISymm *)hSymmKeyObj;
    std::vector<unsigned char> vInData;
    std::vector<unsigned char> vOutData;
    vInData.assign(pucInData, pucInData + uiInDataLen);
    encryptor->Update(vInData, vOutData);
    if (*puiOutDataLen < vOutData.size()) {
        return error::Code::IndataLenErr;
    }
    memcpy(pucOutData, vOutData.data(), vOutData.size());
    *puiOutDataLen = vOutData.size();
    return error::Code::Ok;
}

int CY_SAF_SymmEncryptFinal(
        void *hSymmKeyObj,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen)
{
    DCHECK_NUL(hSymmKeyObj, puiOutDataLen);
    auto *encryptor = (ISymm *)hSymmKeyObj;
    std::vector<unsigned char> vOutData;
    encryptor->Final(vOutData);
    if (pucOutData == nullptr) {
        return error::Code::Ok;
    }
    if (*puiOutDataLen < vOutData.size()) {
        return error::Code::IndataLenErr;
    }
    memcpy(pucOutData, vOutData.data(), vOutData.size());
    *puiOutDataLen = vOutData.size();
    return error::Code::Ok;
}

int CY_SAF_SymmDecrypt(
        void *hSymmKeyObj,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen)
{
    DCHECK_NUL(hSymmKeyObj, pucInData, puiOutDataLen);
    auto *encryptor = (ISymm *)hSymmKeyObj;
    std::vector<unsigned char> vInData;
    std::vector<unsigned char> vOutData1;
    vInData.assign(pucInData, pucInData + uiInDataLen);
    encryptor->Update(vInData, vOutData1);
    std::vector<unsigned char> vOutData2;
    encryptor->Final(vOutData2);
    if (pucOutData == nullptr) {
        *puiOutDataLen = vOutData1.size() + vOutData2.size();
        return error::Code::Ok;
    }
    if (*puiOutDataLen < vOutData1.size() + vOutData2.size()) {
        return error::Code::IndataLenErr;
    }
    memcpy(pucOutData, vOutData1.data(), vOutData1.size());
    memcpy(pucOutData + vOutData1.size(), vOutData2.data(), vOutData2.size());
    *puiOutDataLen = vOutData1.size() + vOutData2.size();
    return error::Code::Ok;
}

int CY_SAF_SymmDecryptUpdate(
        void *hSymmKeyObj,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen)
{
    DCHECK_NUL(hSymmKeyObj, pucInData, pucOutData, puiOutDataLen);
    auto *encryptor = (ISymm *)hSymmKeyObj;
    std::vector<unsigned char> vInData, vOutData;
    vInData.assign(pucInData, pucInData + uiInDataLen);
    encryptor->Update(vInData, vOutData);
    if (*puiOutDataLen < vOutData.size()) {
        return error::Code::IndataLenErr;
    }
    memcpy(pucOutData, vOutData.data(), vOutData.size());
    *puiOutDataLen = vOutData.size();
    return error::Code::Ok;
}

int CY_SAF_SymmDecryptFinal(
        void *hSymmKeyObj,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen)
{
    DCHECK_NUL(hSymmKeyObj, puiOutDataLen);
    auto *encryptor = (ISymm *)hSymmKeyObj;
    std::vector<unsigned char> vOutData;
    encryptor->Final(vOutData);
    if (pucOutData == nullptr) {
        return error::Code::Ok;
    }
    if (*puiOutDataLen < vOutData.size()) {
        return error::Code::IndataLenErr;
    }
    memcpy(pucOutData, vOutData.data(), vOutData.size());
    *puiOutDataLen = vOutData.size();
    return error::Code::Ok;
}

int CY_SAF_Hmac(
        unsigned int uiHashAlgoType,
        unsigned char * pucInKey,
        unsigned int uiInKeyLen,
        const unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen)
{
    DCHECK_NUL(pucInKey, pucInData, pucOutData, puiOutDataLen);
    int rv = error::Code::UnknownErr;
    std::vector<unsigned char> vInData;
    HMAC::ptr iHmac;
    std::string sAlgorithm;
    FUNC_ENTRY;
    switch (uiHashAlgoType) {
        case SGD_SM3:    sAlgorithm = "SM3";    break;
        case SGD_SHA1:   sAlgorithm = "SHA1";   break;
        case SGD_SHA256: sAlgorithm = "SHA256"; break;
        case SGD_SHA512: sAlgorithm = "SHA512"; break;
        default:         sAlgorithm = "NONE";   break;
    }
    FUNC_PARAMETER(sAlgorithm);
    iHmac = HMAC::CreateHmac(sAlgorithm);
    if (iHmac == nullptr) {
        rv = error::Code::ObjErr;
        goto cleanup;
    }
    vInData.assign(pucInData, pucInData + uiInDataLen);
    if (!iHmac->Init(pucInKey, uiInKeyLen) ||
        !iHmac->Update(pucInData, uiInDataLen) ||
        !iHmac->Final(pucOutData, puiOutDataLen)) {
        rv = error::Code::UnknownErr;
        goto cleanup;
    }
    rv = error::Code::Ok;
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_Hkdf(
        unsigned int uiHashAlgoType,
        unsigned char *pucIkm,
        unsigned int uiIkmLen,
        unsigned char *pucSaltData,
        unsigned int uiSaltDataLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucOutData,
        unsigned int puiOutDataLen)
{
    DCHECK_NUL(pucIkm, pucSaltData, pucInData, pucOutData);
    int rv = error::Code::UnknownErr;
    std::vector<unsigned char> vIkm, vInfo, vSalt, vOutData;
    vIkm.assign(pucIkm, pucIkm + uiIkmLen);
    vInfo.assign(pucInData, pucInData + uiInDataLen);
    vSalt.assign(pucSaltData, pucSaltData + uiSaltDataLen);
    std::string sAlgorithm;
    FUNC_ENTRY;
    switch (uiHashAlgoType) {
        case SGD_SM3:    sAlgorithm = "SM3";    break;
        case SGD_SHA1:   sAlgorithm = "SHA1";   break;
        case SGD_SHA256: sAlgorithm = "SHA256"; break;
        case SGD_SHA512: sAlgorithm = "SHA512"; break;
        default:         sAlgorithm = "NONE";   break;
    }
    FUNC_PARAMETER(sAlgorithm);
    std::shared_ptr<IHkdf> iHkdf = Hkdf::CreateHkdf(sAlgorithm);
    if (iHkdf == nullptr) {
        rv = error::Code::ObjErr;
        goto cleanup;
    }
    if (!iHkdf->Compute(vIkm, vInfo, vSalt, puiOutDataLen, vOutData)) {
        rv = error::Code::UnknownErr;
        goto cleanup;
    }
    memcpy(pucOutData, vOutData.data(), vOutData.size());
    rv = error::Code::Ok;
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}