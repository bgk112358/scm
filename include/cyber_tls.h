// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef SVKD_BUILD_cyber_TLS_H
#define SVKD_BUILD_cyber_TLS_H

#ifdef __cpulsplus
extern "C" {
#endif

/**
 * @brief 获取 Openssl Context
 *
 * @param hAppHandle                 [IN] 应用接口句柄
 * @param pucContainerName           [IN] 容器名称
 * @param uiContainerNameLen         [IN] 容器名称长度
 * @param pucPin                     [IN] 设备口令
 * @param uiPinLen                   [IN] 设备口令长度
 * @param ctx                        [OUT] SSL_CTX
 * @return 0 成功 / 非 0 失败，返回错误码
 */
int CY_GetSSLContext(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        void **ctx);

#ifdef __cpulsplus
}
#endif

#endif //SVKD_BUILD_cyber_TLS_H
