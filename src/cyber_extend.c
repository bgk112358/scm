// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "cyber_extend.h"
#include "external/cyber_saf.h"
#include "external/cyber_thread.h"

int CY_ExportP12Certificate(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int   uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int   uiPinLen,
        const char    *pcPassword,
        unsigned char *pucCertificate,
        unsigned int  *puiCertificateLen)
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
    rv = CY_SAF_ExportP12Certificate(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            pcPassword,
            pucCertificate,
            puiCertificateLen);
cleanup:
    CY_SAF_Logout(
            hAppHandle,
            0);
    CY_UnLock(0);
    return rv;

}