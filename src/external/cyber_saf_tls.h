// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef SCM_CYBER_SAF_TLS_H
#define SCM_CYBER_SAF_TLS_H

#ifdef __cplusplus
extern "C" {
#endif

int CY_SAF_GetSSLContext(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        void **ctx);

#ifdef __cplusplus
}
#endif

#endif // SCM_CYBER_SAF_TLS_H
