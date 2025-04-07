// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_cyber_INTERNAL_H
#define CYBERLIB_BUILD_cyber_INTERNAL_H

#include "cyber_define.h"

#ifdef __cpulsplus
extern "C" {
#endif

/**
 * @brief 导出 P12 证书
 *
 * @param phAppHandle              [IN]  输入并返回应用接口句柄
 * @param pucContainerName         [IN]  容器名称，需要传入已有密钥容器。
 * @param uiContainerNameLen       [IN]  容器名称长度
 * @param pucPin                   [IN]  设备口令
 * @param uiPinLen                 [IN]  设备口令长度
 * @param pucCertificate           [OUT] P12 格式证书
 * @param puiCertificateLen        [OUT] P12 格式证书长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_ExportP12Certificate(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int   uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int   uiPinLen,
        const char   *pcPassword,
        unsigned char *pucCertificate,
        unsigned int  *puiCertificateLen);

#ifdef __cpulsplus
}
#endif
#endif //CYBERLIB_BUILD_cyber_INTERNAL_H