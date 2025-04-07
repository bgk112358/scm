//
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//

#include <cstring>
#include "cyber_saf.h"
#include "handle/handler.h"
#include "common/common.h"
#include "util/util.h"

#if defined(ENABLE_DRIVER)
#include "engine/engine_factory.h"
#endif

using namespace cyber;

int CY_SAF_Initialize(
        void **phAppHandle,
        Application_st *pApplication)
{
    int rv = error::Code::NotInitializeErr;
    auto *handler = static_cast<Handler *>(*phAppHandle);
    if (pApplication == nullptr) {
        rv = error::Code::IndataErr;
        goto cleanup;
    }
    if (handler == nullptr) {
        handler = Handler::Instance();
    }
    handler->SetFolderName(pApplication->AppPath);
    if (!handler->Initialize()) {
        goto cleanup;
    }
    FUNC_ENTRY;
    FUNC_PARAMETER(handler);
    FUNC_PARAMETER(PROJECT_VERSION);
    FUNC_PARAMETER(handler->GetFolderName());
    *phAppHandle = handler;
    rv = error::Code::Ok;
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_Finalize(
        void *hAppHandle)
{
    int rv = error::Code::IndataErr;
    Handler *handler;
    FUNC_ENTRY;
    if (hAppHandle == nullptr) {
        goto cleanup;
    }
    FUNC_PARAMETER(hAppHandle);
    handler = (Handler *)hAppHandle;
    handler->UnInitialize();
    rv = error::Code::Ok;
cleanup:
    FUNC_EXIT_RV(rv);
    return rv;
}

int CY_SAF_GetVersion(
        char *pcVersion)
{
    if (pcVersion == nullptr) {
        return error::Code::IndataErr;
    }
    const char* version = PROJECT_VERSION;
    strcpy(pcVersion, version);
    return error::Code::Ok;
}

int CY_SAF_Login(
        void *hAppHandle,
        unsigned int uiUsrType,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        unsigned int *puiRemainCount)
{
    DCHECK_NUL(hAppHandle, pucContainerName);
    (void)uiUsrType;
    auto handle = (Handler *)hAppHandle;
    std::string containerName(
            reinterpret_cast<const char *>(pucContainerName),
            uiContainerNameLen);
    handle->SetContainerName(containerName.c_str());
    if (pucPin != nullptr) {
        std::string containerPin(reinterpret_cast<const char *>(pucPin), uiPinLen);
        handle->SetContainerPin(containerPin.c_str());
    }
    return error::Code::Ok;
}

int CY_SAF_ChangePin(
        void *hAppHandle,
        unsigned int uiUsrType,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucOldPin,
        unsigned int uiOldPinLen,
        unsigned char *pucNewPin,
        unsigned int uiNewPinLen,
        unsigned int *puiRemainCount)
{
    (void)hAppHandle;
    (void)uiUsrType;
    (void)uiContainerNameLen;
    (void)uiOldPinLen;
    (void)uiNewPinLen;
    return error::Code::NotSupportYetErr;
}

int CY_SAF_Logout(
        void *hAppHandle,
        unsigned int uiUsrType)
{
    if (hAppHandle == nullptr) {
        return error::Code::IndataErr;
    }
    (void)uiUsrType;
    auto handle = (Handler *)hAppHandle;
    handle->SetContainerName("");
    handle->SetContainerPin("");
#if defined(ENABLE_DRIVER)
    if (handle->isHardWare()) {
        int rv = EngineFactory::Logout(uiUsrType);
        if (rv != CYBER_R_SUCCESS) {
            return rv;
        }
    }
#endif
    return error::Code::Ok;
}