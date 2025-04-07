// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#include "cyber_saf.h"
#include "handle/handler.h"
#include "util/util.h"
#include "container/container_resolver.h"
#include "common/common.h"
#include "util/path_utils.h"

using namespace cyber;

int CY_SAF_InternalGetContainerPath(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiContainerType,
        char *pcContainerPath,
        unsigned int uiContainerPathLen)
{
    DCHECK_NUL(hAppHandle, pcContainerPath);
    auto *handle = static_cast<Handler *>(hAppHandle);
    if (!handle->isInitialized()) {
        LOGM(ERROR,"NOT Initalized\n");
        return error::Code::NotInitializeErr;
    }
    std::string containerName;
    if (pucContainerName) {
        containerName.assign((char *)pucContainerName, uiContainerNameLen);
    }
    std::string filePath = PathUtils::HashPath(
            handle->GetFolderName(),
            containerName, (int)uiContainerType);
    if (uiContainerPathLen < filePath.length()) {
        return error::Code::IndataLenErr;
    }
    
    memcpy(pcContainerPath, filePath.c_str(), filePath.length());
    
    return error::Code::Ok;
}

int CY_SAF_InternalWriteContainer(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int  uiContainerNameLen,
        unsigned int  uiContainerType,
        unsigned char *pucContainerData,
        unsigned int  uiContainerDataLen)
{
    char pcContainerPath[SGD_MAX_SIZE] = {0};
    int rv = CY_SAF_InternalGetContainerPath(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiContainerType,
            pcContainerPath,
            SGD_MAX_SIZE);
    if (rv != error::Code::Ok) {
        LOGM(ERROR, "InternalGetContainerPath fail " + std::string(pcContainerPath));
        return rv;
    }
    if (!IoUtils::WriteFile(pcContainerPath, pucContainerData, uiContainerDataLen)) {
        LOGM(ERROR, "WriteToFile fail.");
        return error::Code::FileErr;
    }
    return rv;
}

int CY_SAF_InternalReadContainer(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int  uiContainerNameLen,
        unsigned int  uiContainerType,
        unsigned char *pucPin,
        unsigned int  uiPinLen,
        unsigned int  *uiContainerUsage,
        unsigned char *pucContainerData,
        unsigned int  *uiContainerDataLen)
{
    DCHECK_NUL(hAppHandle, pucContainerName);
    char pcContainerPath[SGD_MAX_SIZE] = {0};
    std::vector<unsigned char> vPinData, vInData;
    int rv = CY_SAF_InternalGetContainerPath(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiContainerType,
            pcContainerPath,
            SGD_MAX_SIZE);
    if (rv != error::Code::Ok) {
        LOGM(INFO, "GetContainerPath fail, file code: " + std::to_string(rv));
        return rv;
    }
    if (!FileUtils::IsExist(pcContainerPath)) {
        LOGM(INFO, "File does not exist, file path: " << pcContainerPath);
        return error::Code::FileNotFoundErr;
    }
    if (!IoUtils::ReadFile(pcContainerPath, vInData)) {
        LOGM(ERROR, "ReadFromFile fail, fail code: " + std::to_string(rv));
        return error::Code::NotExportErr;
    }
    if (pucPin) {
        vPinData.assign(pucPin, pucPin + uiPinLen);
    }
    ContainerResolver containerResolver = ContainerResolver(vInData);
    rv = containerResolver.Resolver(vPinData);
    if (rv != error::Code::Ok) {
        return rv;
    }
    if (uiContainerUsage) *uiContainerUsage = containerResolver.GetUsage();
    vInData = containerResolver.GetPlainData();
    if (pucContainerData == nullptr) {
        *uiContainerDataLen = vInData.size();
        return error::Code::Ok;
    }
    if (*uiContainerDataLen < vInData.size()) {
        return error::Code::IndataLenErr;
    }
    memcpy(pucContainerData, vInData.data(), vInData.size());
    *uiContainerDataLen = vInData.size();
    return error::Code::Ok;
}

int CY_SAF_InternalExportPrivateKey(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int  uiSignFlag,
        unsigned int  *uiAlgorithm,
        unsigned char *pucData,
        unsigned int  *uiDataLen)
{
    DCHECK_NUL(hAppHandle, pucContainerName, uiDataLen);
    unsigned int uiContainerType = ENC_KEY;
    if (uiSignFlag) {
        uiContainerType = SIGN_KEY;
    }
    auto *handler = static_cast<Handler *>(hAppHandle);
    // Container Path
    char pcContainerPath[SGD_MAX_SIZE] = {0};
    int rv = CY_SAF_InternalGetContainerPath(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            uiContainerType,
            pcContainerPath,
            SGD_MAX_SIZE);
    if (rv != error::Code::Ok) {
        LOGM(ERROR, "GetContainerPath fail, fail code: " + std::to_string(rv));
        return rv;
    }
    if (!FileUtils::IsExist(pcContainerPath)) {
        LOGM(ERROR, "KeyNotFound, filePath: " << pcContainerPath);
        return error::Code::KeyNotFoundErr;
    }
    // Private Key
    std::vector<unsigned char> vInData;
    if (!IoUtils::ReadFile(pcContainerPath, vInData)) {
        LOGM(ERROR, "ReadFromFile fail, fail code: " + std::to_string(rv));
        return error::Code::NotExportErr;
    }
    std::vector<unsigned char> vPinData;
    std::string spin = handler->GetContainerPin();
    auto *pValue = (unsigned char *)spin.c_str();
    vPinData.assign(pValue, pValue + spin.size());
    ContainerResolver containerResolver = ContainerResolver(vInData);
    rv = containerResolver.Resolver(vPinData);
    if (rv != error::Code::Ok) {
        LOGM(ERROR, "Resolver container fail, fail code: " << std::hex << rv);
        return rv;
    }
    // Algorithm
    if (uiAlgorithm) *uiAlgorithm = containerResolver.GetAlgIdentify();
    // Data
    std::vector<unsigned char> vOutData = containerResolver.GetPlainData();
    if (pucData) {
        memcpy(pucData, vOutData.data(), vOutData.size());
    }
    if (uiDataLen) *uiDataLen = vOutData.size();
    if (*uiDataLen < vOutData.size()) {
        return error::Code::IndataErr;
    }
    *uiDataLen = vOutData.size();
    return error::Code::Ok;
}

int CY_SAF_InternalGetUUID(
        void *hAppHandle,
        unsigned char *pucData,
        unsigned int *uiDataLen)
{
    DCHECK_NUL(hAppHandle, pucData, uiDataLen);
    unsigned int uiContainerType = UUID;
    // Container Path
    char pcContainerPath[SGD_MAX_SIZE] = {0};
    unsigned char ucContainerName[] = "uuid";
    unsigned int  uiContainerNameLen = 4;
    auto handle = (Handler *)hAppHandle;
    int rv = CY_SAF_InternalGetContainerPath(
            hAppHandle,
            ucContainerName,
            uiContainerNameLen,
            uiContainerType,
            pcContainerPath,
            SGD_MAX_SIZE);
    if (rv != error::Code::Ok) {
        LOGM(ERROR, "GetContainerPath fail, fail code: " + std::to_string(rv));
        return rv;
    }
    std::string sClientType = handle->GetClientType();
    bool res = FileUtils::IsExist(pcContainerPath);
    if (res) {
        std::vector<unsigned char> vData;
        res = IoUtils::ReadFile(pcContainerPath, vData);
        if (res && (*uiDataLen > vData.size())) {
            memcpy(pucData, vData.data(), vData.size());
            memcpy(pucData + vData.size(), sClientType.c_str(), sClientType.size());
            *uiDataLen = vData.size() + sClientType.size();
            return error::Code::Ok;
        }
    }
    std::string virtual_identify = UUIDUtils::Generate();
    IoUtils::WriteFile(pcContainerPath,
                       (unsigned char *) virtual_identify.data(), virtual_identify.length());
    memcpy(pucData, virtual_identify.c_str(), virtual_identify.size());
    memcpy(pucData + virtual_identify.size(), sClientType.c_str(), sClientType.size());
    *uiDataLen = virtual_identify.size() + sClientType.size();
    return error::Code::Ok;
}