//
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//

#ifndef SCM_CYBER_PKI_H
#define SCM_CYBER_PKI_H

#include <stdint.h>
#include "cyber_define.h"
#include "cyber_error.h"

#ifdef __cpulsplus
extern "C" {
#endif

/* ******************************************
           Environment interface
****************************************** */

/**
 * @brief 初始化密码服务
 *
 * @param phAppHandle     [IN/OUT] 输入并返回应用接口句柄
 * @param pcAppFilePath   [IN]     应用存储路径
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_InitService(
        void **phAppHandle,
        const char *pcAppFilePath);

/**
 * @brief 清除密码服务
 *
 * @param phAppHandle     [IN] 应用接口句柄
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_Finalize(void *hAppHandle);

/**
 * @brief 获取 lib 版本信息
 *
 * @param pcVersion       [OUT] 版本号
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_GetVersion(char *pcVersion);

/* ******************************************
           Certificate interface
 ****************************************** */

/**
 * @brief 导入信任的证书链
 *
 * @param hAppHandle              [IN] 应用接口句柄
 * @param pucCertificates         [IN] PEM 编码的证书链
 * @param uiCertificatesLen       [IN] PEM 证书链长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_ImportTrustedCertificateChain(
        void *hAppHandle,
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen);

/**
 * @brief 获取信任的证书链
 *
 * @param hAppHandle              [IN]  应用接口句柄
 * @param pucCertificates         [OUT] PEM 格式的证书
 * @param puiCertificatesLen      [OUT] PEM 证书长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_GetTrustedCertificateChain(
        void *hAppHandle,
        unsigned char *pucCertificates,
        unsigned int *puiCertificatesLen);

/**
 * @brief 删除信任的证书链
 *
 * @param hAppHandle              [IN] 应用接口句柄
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_RemoveTrustedCertificateChain(void *hAppHandle);

/**
 * @brief 生成证书请求文件
 *
 * @param hAppHandle               [IN]  应用接口句柄
 * @param pucContainerName         [IN]  容器名称，需要传入已有密钥容器。
 * @param uiContainerNameLen       [IN]  容器名称长度
 * @param pucPin                   [IN]  设备口令
 * @param uiPinLen                 [IN]  设备口令长度
 * @param pstNameInfo              [IN]  请求信息
 * @param pucCertificateRequest    [OUT] Der 格式证书请求文件
 * @param puiCertificateRequestLen [OUT] Der 格式证书请求文件长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_GenerateCertificateSigningRequest(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        SGD_NAME_INFO *pstNameInfo,
        unsigned char *pucCertificateRequest,
        unsigned int *puiCertificateRequestLen);

/**
 * @brief 检查本地证书状态
 *
 * @param hAppHandle          [IN]  应用接口句柄
 * @param pucContainerName    [IN]  容器名称
 * @param uiContainerNameLen  [IN]  容器名称长度
 * @param pucPin              [IN]  设备口令（Optional 为 NULL 则不校验私钥与证书是否匹配）
 *                                  如拉取 OTA 业务证书时，本地没有 OTA 私钥，该参数则传 NULL
 * @param uiPinLen            [IN]  设备口令长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
int CY_GetCertificateStatus(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int   uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int  uiPinLen);

/**
 * @brief 导入用户证书
 *
 * @param hAppHandle          [IN] 应用接口句柄
 * @param pucContainerName    [IN] 容器名称
 * @param uiContainerNameLen  [IN] 容器名称长度
 * @param uiSignFlag          [IN] 1 表示签名证书，0 表示加密证书
 * @param pucCertificate      [IN] 证书内容缓冲区
 * @param uiCertificate       [IN] 证书长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
int CY_ImportCertificate(
        void  *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int   uiContainerNameLen,
        unsigned int   uiSignFlag,
        unsigned char *pucCertificate,
        unsigned int   uiCertificateLen);

/**
 * @brief 导出用户证书
 *
 * @param hAppHandle          [IN]  应用接口句柄
 * @param pucContainerName    [IN]  容器名称
 * @param uiContainerNameLen  [IN]  容器名称长度
 * @param uiSignFlag          [IN]  1 表示签名证书，0 表示加密证书
 * @param pucCertificate      [OUT] 指向证书内容缓冲区
 * @param puiCertificate      [IN/OUT] 输入时候表示证书缓冲区长度，输出表示证书内容长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
int CY_ExportCertificate(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int   uiContainerNameLen,
        unsigned int   uiSignFlag,
        unsigned char *pucCertificate,
        unsigned int  *puiCertificateLen);

/**
 * @brief 删除用户证书
 *
 * @param hAppHandle          [IN] 应用接口句柄
 * @param pucContainerName    [IN] 容器名称
 * @param uiContainerNameLen  [IN] 容器名称长度
 * @param uiSignFlag          [IN] 1 表示签名证书，0 表示加密证书
 * @return 0 成功 / 非 0 失败，返回错误码
 */
int CY_RemoveCertificate(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int   uiContainerNameLen,
        unsigned int   uiSignFlag);

/**
 * @brief 验证用户证书的有效性，包括验证有效期，证书信任列表，不包含吊销状态。
 *
 * @param hAppHandle          [IN] 应用接口句柄
 * @param pucUsrCertificate   [IN] PEM 编码的证书
 * @param uiUsrCertificateLen [IN] 证书长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_VerifyCertificate(
        void *hAppHandle,
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen);

/**
 * @brief 验证用户证书的有效性，包括验证有效期，证书信任列表，包含吊销状态。
 *
 * @param hAppHandle          [IN] 应用接口句柄
 * @param pucUsrCertificate   [IN] PEM 编码证书
 * @param uiUsrCertificateLen [IN] 证书长度
 * @param pucPemCrl           [IN] PEM 编码的 CRL，若为 NULL 则根据证书中的 CRL 地址下载。
 * @param uiDerPemLen         [IN] CRL 长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
int CY_VerifyCertificateByCrl(
        void *hAppHandle,
        unsigned char *pucUsrCertificate,
        unsigned int uiUsrCertificateLen,
        unsigned char *pucPemCrl,
        unsigned int uiDerPemLen);


/**
 * @brief 解析证书，获取证书中的信息
 *
 * @param pucCertificate      [IN] PEM 编码的证书
 * @param uiCertificateLen    [IN] 证书长度
 * @param uiInfoType          [IN] 制定的证书解析标识，见: 证书解析项标识
 * @param pucInfo             [OUT] 获取的证书信息
 * @param puiInfoLen          [OUT] 获取的证书信息长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
int CY_GetCertificateInfo(
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        unsigned int uiInfoType,
        unsigned char *pucInfo,
        unsigned int *puiInfoLen);

/* ******************************************
      Cryptographic algorithm interface
 ****************************************** */

/**
 * @brief Base 64 编码
 *
 * @param pucInData       [IN]  编码前的数据
 * @param puiInDataLen    [IN]  编码前的数据长度
 * @param pucOutData      [OUT] 编码后的数据
 * @param puiOutDataLen   [IN/OUT] 输入时表示编码结果的缓冲区大小，输出时表示编码结果长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_Base64_Encode(
        unsigned char *pucInData,
        unsigned int puiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen);

/**
 * @brief Base 64 解码
 *
 * @param pucInData       [IN]  解码前的数据
 * @param puiInDataLen    [IN]  解码前的数据长度
 * @param pucOutData      [OUT] 解码后的数据
 * @param puiOutDataLen   [IN/OUT] 输入时表示解码结果的缓冲区大小，输出时表示解码结果长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_Base64_Decode(
        unsigned char *pucInData,
        unsigned int puiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen);

/**
 * 生成随机数
 *
 * @param uiRandLen       [IN]  随机数长度
 * @param pucRand         [OUT] 随机数
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_GenRandom(
        unsigned int uiRandLen,
        unsigned char *pucRand);

/**
 * @brief HASH 运算
 *
 * @param uiHashAlgoType   [IN]  HASH 算法，见：哈希算法标识
 * @param pucInData        [IN]  输入数据
 * @param uiInDataLen      [IN]  输入数据长度
 * @param pucOutData       [OUT]    HASH
 * @param puiOutDataLen    [IN/OUT] 输入时候表示哈希缓冲区长度，输出表示哈希内容长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_Hash(
        unsigned int uiHashAlgoType,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen);

/**
 * @brief 创建 Hash 对象
 *
 * @param phHashObj     [IN/OUT] 哈希对象
 * @param uiAlgoType    [IN]     哈希算法，见 哈希算法标识
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_CreateHashObj(
        void **phHashObj,
        unsigned int uiHashAlgoType);

/**
 * @brief 销毁 Hash 对象
 *
 * @param hHashObj      [IN] Hash 对象
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_DestroyHashObj(
        void *hHashObj);

/**
 * @brief 多块 Hash 运算
 *
 * @param hHashObj      [IN]  Hash 对象
 * @param pucInData     [IN]  输入数据
 * @param uiInDataLen   [IN]  输入数据长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_HashUpdate(
        void *hHashObj,
        unsigned char *pucInData,
        unsigned int uiInDataLen);

/**
 * 结束 Hash 运算
 *
 * @param hHashObj      [IN]  Hash 对象
 * @param pucOutData    [OUT] 输出的 Hash 值
 * @param uiOutDataLen  [IN/OUT] 输入时候表示哈希值缓冲区长度，输出表示哈希值长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_HashFinal(
        void *hHashObj,
        unsigned char *pucOutData,
        unsigned int *uiOutDataLen);

/**
 * @brief 生成 RSA 密钥对
 *
 * @param hAppHandle         [IN] 应用接口句柄
 * @param pucContainerName   [IN] 容器名称
 * @param uiContainerNameLen [IN] 容器名称长度
 * @param pucPin             [IN] 设备口令
 * @param uiPinLen           [IN] 设备口令长度
 * @param uiKeyBits          [IN] 密钥长度 支持 2048, 3072, 4096
 * @param uiKeyUsage         [IN] 密钥用途 SGD_KEYUSAGE_SIGN（签名）SGD_KEYUSAGE_ENC（加密）
 * @param uiExportFlag       [IN] 是否可导出密钥（仅对私钥有效）, 0 不可导出，1 可导出
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_GenRsaKeyPair(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        unsigned int uiKeyBits,
        unsigned int uiKeyUsage,
        unsigned int uiExportFlag);

/**
 * @brief 获取 RSA 公钥
 *
 * @param hAppHandle         [IN] 应用接口句柄
 * @param pucContainerName   [IN] 容器名称
 * @param uiContainerNameLen [IN] 容器名称长度
 * @param uiKeyUsage         [IN] 密钥用途 SGD_KEYUSAGE_SIGN（签名）SGD_KEYUSAGE_ENC（加密）
 * @param pucPublicKey       [OUT] DER 格式公钥
 * @param puiPublicKeyLen    [OUT] DER 格式公钥长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_GetRsaPublicKey(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiKeyUsage,
        unsigned char *pucPublicKey,
        unsigned int *puiPublicKeyLen);

/**
 * @brief 私钥签名（PKCS1-v1_5 模式）
 *
 * @param hAppHandle         [IN] 应用接口句柄
 * @param pucContainerName   [IN] 容器名称
 * @param uiContainerNameLen [IN] 容器名称长度
 * @param pucPin             [IN] 设备口令
 * @param uiPinLen           [IN] 设备口令长度
 * @param uiHashAlgoType     [IN] 密码杂凑算法标识
 * @param pucInData          [IN] 原始数据
 * @param uiInDataLen        [IN] 原始数据的长度
 * @param pucSignature       [OUT] 输出的 DER 格式的签名结果
 * @param puiSignatureLen    [IN/OUT] 输入时候表示签名缓冲区长度，输出表示签名内容长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_RsaSign(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        unsigned int uiHashAlgoType,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen);

/**
 * @brief 私钥签名（PSS 模式）
 *
 * @param hAppHandle         [IN] 应用接口句柄
 * @param pucContainerName   [IN] 容器名称
 * @param uiContainerNameLen [IN] 容器名称长度
 * @param pucPin             [IN] 设备口令
 * @param uiPinLen           [IN] 设备口令长度
 * @param uiHashAlgoType     [IN] 密码杂凑算法标识
 * @param pucInData          [IN] 原始数据
 * @param uiInDataLen        [IN] 原始数据的长度
 * @param pucSignature       [OUT] 输出的 DER 格式的签名结果
 * @param puiSignatureLen    [IN/OUT] 输入时候表示签名缓冲区长度，输出表示签名内容长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_RsaSignPss(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        unsigned int uiHashAlgoType,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen);

/**
 * @brief 对文件进行 RSA 签名运算（PKCS1-v1_5 模式）
 *
 * @param hAppHandle         [IN] 应用接口句柄
 * @param pucContainerName   [IN] 密钥的容器名
 * @param uiContainerNameLen [IN] 密钥容器名长度
 * @param pucPin             [IN] 设备口令
 * @param uiPinLen           [IN] 设备口令长度
 * @param uiHashAlgoType     [IN] 密码杂凑算法标识
 * @param pucFileName        [IN] 要签名的全路径文件名
 * @param pucSignature       [OUT] 输出的 DER 格式的签名结果
 * @param puiSignatureLen    [IN/OUT] 输入时候表示签名缓冲区长度，输出表示签名内容长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_RsaSignFile(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        unsigned int uiHashAlgoType,
        const char *pcFileName,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen);

/**
 * @brief 对文件进行 RSA 签名运算（PSS 模式）
 *
 * @param hAppHandle         [IN] 应用接口句柄
 * @param pucContainerName   [IN] 密钥的容器名
 * @param uiContainerNameLen [IN] 密钥容器名长度
 * @param pucPin             [IN] 设备口令
 * @param uiPinLen           [IN] 设备口令长度
 * @param uiHashAlgoType     [IN] 密码杂凑算法标识
 * @param pucFileName        [IN] 要签名的全路径文件名
 * @param pucSignature       [OUT] 输出的 DER 格式的签名结果
 * @param puiSignatureLen    [IN/OUT] 输入时候表示签名缓冲区长度，输出表示签名内容长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_RsaSignFilePss(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        unsigned int uiHashAlgoType,
        const char *pcFileName,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen);

/**
 * @brief RSA 验证签名运算（PKCS1-v1_5 模式）
 *
 * @param uiHashAlgoType     [IN] 密码杂凑算法标识
 * @param pucPublicKey       [IN] DER 编码的公钥
 * @param uiPublicKeyLen     [IN] DER 编码的公钥长度
 * @param pucInData          [IN] 原始数据
 * @param uiInDataLen        [IN] 原始数据长度
 * @param pucSignData        [IN] DER 编码的签名数据
 * @param uiSignDataLen      [IN] 签名数据长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_RsaVerifySign(
        unsigned int uiHashAlgoType,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignData,
        unsigned int uiSignDataLen);

/**
 * @brief RSA 验证签名运算（PSS 模式）
 *
 * @param uiHashAlgoType     [IN] 密码杂凑算法标识
 * @param pucPublicKey       [IN] DER 编码的公钥
 * @param uiPublicKeyLen     [IN] DER 编码的公钥长度
 * @param pucInData          [IN] 原始数据
 * @param uiInDataLen        [IN] 原始数据长度
 * @param pucSignData        [IN] DER 编码的签名数据
 * @param uiSignDataLen      [IN] 签名数据长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_RsaVerifySignPss(
        unsigned int uiHashAlgoType,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignData,
        unsigned int uiSignDataLen);

/**
 * @brief 对文件进行 RSA 验签（PKCS1-v1_5 模式）
 *
 * @param uiHashAlgoType     [IN] 密码杂凑算法标识
 * @param pucPublicKey       [IN] DER 编码的公钥
 * @param uiPublicKeyLen     [IN] DER 编码的公钥长度
 * @param pucFileName        [IN] 要验证签名的全路径文件名
 * @param pucSignData        [IN] DER 编码的签名数据
 * @param uiSignDataLen      [IN] 签名数据长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_RsaVerifySignFile(
        unsigned int uiHashAlgoType,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        const char *pucFileName,
        unsigned char *pucSignData,
        unsigned int uiSignDataLen);

/**
 * @brief 对文件进行 RSA 验签（PSS 模式）
 *
 * @param uiHashAlgoType     [IN] 密码杂凑算法标识
 * @param pucPublicKey       [IN] DER 编码的公钥
 * @param uiPublicKeyLen     [IN] DER 编码的公钥长度
 * @param pucFileName        [IN] 要验证签名的全路径文件名
 * @param pucSignData        [IN] DER 编码的签名数据
 * @param uiSignDataLen      [IN] 签名数据长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_RsaVerifySignFilePss(
        unsigned int uiHashAlgoType,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        const char *pucFileName,
        unsigned char *pucSignData,
        unsigned int uiSignDataLen);

/**
 * @brief 使用数字证书对签名值进行验证（PKCS1-v1_5 模式）
 *
 * @param uiHashAlgoType     [IN] 密码杂凑算法标识
 * @param pucCertificate     [IN] DER 编码的数字证书
 * @param uiCertificateLen   [IN] DER 编码的数字证书长度
 * @param pucInData          [IN] 原始数据
 * @param uiInDataLen        [IN] 原始数据的长度
 * @param pucSignData        [IN] 签名数据
 * @param uiSignDataLen      [IN] 签名数据长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_RsaVerifySignByCert(
        unsigned int uiHashAlgoType,
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignData,
        unsigned int uiSignDataLen);

/**
 * @brief 使用数字证书对签名值进行验证（PSS 模式）
 *
 * @param uiHashAlgoType     [IN] 密码杂凑算法标识
 * @param pucCertificate     [IN] DER 编码的数字证书
 * @param uiCertificateLen   [IN] DER 编码的数字证书长度
 * @param pucInData          [IN] 原始数据
 * @param uiInDataLen        [IN] 原始数据的长度
 * @param pucSignData        [IN] 签名数据
 * @param uiSignDataLen      [IN] 签名数据长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_RsaVerifySignByCertPss(
        unsigned int uiHashAlgoType,
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignData,
        unsigned int uiSignDataLen);

/**
 * @brief 使用数字证书对文件签名值进行验证 （PKCS1-v1_5 模式）
 *
 * @param uiHashAlgoType     [IN] 密码杂凑算法标识
 * @param pucCertificate     [IN] DER 编码的数字证书
 * @param uiCertificateLen   [IN] DER 编码的数字证书长度
 * @param pucFileName        [IN] 要验证签名的全路径文件名
 * @param pucSignature       [IN] DER 编码的签名数据
 * @param uiSignatureLen     [IN] 签名数据长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_RsaVerifySignFileByCert(
        unsigned int uiHashAlgoType,
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        const char *pcFileName,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen);

/**
 * @brief 使用数字证书对文件签名值进行验证 （PSS 模式）
 *
 * @param uiHashAlgoType     [IN] 密码杂凑算法标识
 * @param pucCertificate     [IN] DER 编码的数字证书
 * @param uiCertificateLen   [IN] DER 编码的数字证书长度
 * @param pucFileName        [IN] 要验证签名的全路径文件名
 * @param pucSignature       [IN] DER 编码的签名数据
 * @param uiSignatureLen     [IN] 签名数据长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_RsaVerifySignFileByCertPss(
        unsigned int uiHashAlgoType,
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        const char *pcFileName,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen);

/**
 * @brief RSA 加密
 *
 * @param pucPublicKey       [IN] DER 编码的公钥
 * @param uiPublicKeyLen     [IN] DER 编码的公钥长度
 * @param pucInData          [IN] 待加密数据，长度需小于 RSA bits / 8 - 11
 * @param uiInDataLen        [IN] 带加密数据长度
 * @param pucData            [OUT] 密文数据 采用 RSA_PKCS1_PADDING 填充方式
 * @param puiDataLen         [IN/OUT] 输入时候表示缓冲区长度，输出表示密文长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_RsaEncrypt(
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int  *puiDataLen);

/**
 * @brief 通过证书 RSA 加密
 *
 * @param pucCertificate     [IN] DER 编码的数字证书
 * @param uiCertificateLen   [IN] DER 编码的数字证书长度
 * @param pucInData          [IN] 待加密数据，长度需小于 RSA bits / 8 - 11
 * @param uiInDataLen        [IN] 待加密数据长度
 * @param pucData            [OUT] 密文数据 采用 RSA_PKCS1_PADDING 填充方式
 * @param puiDataLen         [IN/OUT] 输入时候表示缓冲区长度，输出表示密文长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_RsaEncryptByCert(
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int *puiDataLen);

/**
 * @brief RSA 解密
 *
 * @param hAppHandle         [IN] 应用接口句柄
 * @param pucContainerName   [IN] 容器名称
 * @param uiContainerNameLen [IN] 容器名称长度
 * @param pucPin             [IN] 设备口令
 * @param uiPinLen           [IN] 设备口令长度
 * @param pucInData          [IN] 待解密数据
 * @param uiInDataLen        [IN] 待解密数据长度
 * @param pucData            [OUT] 明文数据
 * @param puiDataLen         [IN/OUT] 输入时候表示缓冲区长度，输出表示明文长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_RsaDecrypt(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int *puiDataLen);

/**
 * @brief 生成 ECC 密钥对
 *
 * @param hAppHandle         [IN] 应用接口句柄
 * @param pucContainerName   [IN] 容器名称
 * @param uiContainerNameLen [IN] 容器名称长度
 * @param pucPin             [IN] 设备口令
 * @param uiPinLen           [IN] 设备口令长度
 * @param uiAlgorithmID      [IN] 密钥标识 SGD_SM2, SGD_ECC, SGD_ED25519
 * @param uiKeyUsage         [IN] 密钥用途 SGD_KEYUSAGE_SIGN（签名）SGD_KEYUSAGE_ENC（加密）
 * @param uiExportFlag       [IN] 1 表示生成的密钥可以导出 | 0 表示不可导出
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_GenEccKeyPair(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        unsigned int uiAlgorithmID,
        unsigned int uiKeyUsage,
        unsigned int uiExportFlag);

/**
 * 导入 ECC 密钥对
 *
 * @param hAppHandle         [IN] 应用接口句柄
 * @param pucContainerName   [IN] 容器名称
 * @param uiContainerNameLen [IN] 容器名称长度
 * @param pucPin             [IN] 设备口令
 * @param uiPinLen           [IN] 设备口令长度
 * @param uiAlgorithmID      [IN] 密钥标识 SGD_SM2, SGD_ECC, SGD_ED25519
 * @param uiKeyUsage         [IN] 1 表示签名密钥，0 表示加密密钥
 * @param pucKeyPair         [IN] 密钥对
 * @param uiKeyPairLen       [IN] 密钥对长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_ImportEccKeyPair(
        void  *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int   uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int   uiPinLen,
        unsigned int   uiAlgorithmID,
        unsigned int   uiKeyUsage,
        unsigned char *pucKeyPair,
        unsigned int   uiKeyPairLen);

/**
 * @brief 获取 ECC 公钥
 *
 * @param hAppHandle         [IN] 应用接口句柄
 * @param pucContainerName   [IN] 容器名称
 * @param uiContainerNameLen [IN] 容器名称长度
 * @param uiKeyUsage         [IN] 密钥用途 SGD_KEYUSAGE_SIGN（签名）SGD_KEYUSAGE_ENC（加密）
 * @param pucPublicKey       [OUT] 公钥
 * @param puiPublicKeyLen    [OUT] 公钥长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_GetEccPublicKey(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned int uiKeyUsage,
        unsigned char *pucPublicKey,
        unsigned int *puiPublicKeyLen);

/**
 * @brief ECC 私钥签名
 *
 * @param hAppHandle         [IN] 应用接口句柄
 * @param pucContainerName   [IN] 容器名称
 * @param uiContainerNameLen [IN] 容器名称长度
 * @param pucPin             [IN] 设备口令
 * @param uiPinLen           [IN] 设备口令长度
 * @param uiHashAlgoType     [IN] 密码杂凑算法标识
 * @param pucInData          [IN] 原始数据
 * @param uiInDataLen        [IN] 原始数据的长度
 * @param pucSignature       [OUT] 输出的 DER 格式的签名结果
 * @param puiSignatureLen    [IN/OUT] 输入时候表示签名缓冲区长度，输出表示签名内容长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_EccSign(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        unsigned int uiHashAlgoType,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen);

/**
 * @brief 对文件进行 ECC 签名运算
 *
 * @param hAppHandle         [IN] 应用接口句柄
 * @param pucContainerName   [IN] 密钥的容器名
 * @param uiContainerNameLen [IN] 密钥容器名长度
 * @param pucPin             [IN] 设备口令
 * @param uiPinLen           [IN] 设备口令长度
 * @param uiHashAlgoType     [IN] 密码杂凑算法标识
 * @param pucFileName        [IN] 要签名的全路径文件名
 * @param pucSignature       [OUT] 输出的 DER 格式的签名结果
 * @param puiSignatureLen    [IN/OUT] 输入时候表示签名缓冲区长度，输出表示签名内容长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_EccSignFile(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        unsigned int uiHashAlgoType,
        const char *pcFileName,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen);

/**
 * @brief Ecc 验证签名运算
 *
 * @param uiHashAlgoType     [IN] 密码杂凑算法标识
 * @param pucPublicKey       [IN] DER 编码的公钥
 * @param uiPublicKeyLen     [IN] DER 编码的公钥长度
 * @param pucInData          [IN] 原始数据
 * @param uiInDataLen        [IN] 原始数据长度
 * @param pucSignData        [IN] DER 编码的签名数据
 * @param uiSignDataLen      [IN] 签名数据长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_EccVerifySign(
        unsigned int uiHashAlgoType,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignData,
        unsigned int uiSignDataLen);

/**
 * @brief 对文件进行 ECC 验签
 *
 * @param uiHashAlgoType     [IN] 密码杂凑算法标识
 * @param pucPublicKey       [IN] DER 编码的公钥
 * @param uiPublicKeyLen     [IN] DER 编码的公钥长度
 * @param pucFileName        [IN] 要验证签名的全路径文件名
 * @param pucSignData        [IN] DER 编码的签名数据
 * @param uiSignDataLen      [IN] 签名数据长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_EccVerifySignFile(
        unsigned int uiHashAlgoType,
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        const char *pucFileName,
        unsigned char *pucSignData,
        unsigned int uiSignDataLen);

/**
 * @brief 使用 Ecc 数字证书对签名值进行验证
 *
 * @param uiHashAlgoType     [IN] 密码杂凑算法标识
 * @param pucCertificate     [IN] DER 编码的数字证书
 * @param uiCertificateLen   [IN] DER 编码的数字证书长度
 * @param pucInData          [IN] 原始数据
 * @param uiInDataLen        [IN] 原始数据的长度
 * @param pucSignData        [IN] 签名数据
 * @param uiSignDataLen      [IN] 签名数据长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_EccVerifySignByCert(
        unsigned int uiHashAlgoType,
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignData,
        unsigned int uiSignDataLen);
/**
 * @brief Ecc 加密
 * @param hAppHandle         [IN] 应用接口句柄
 * @param pucPublicKey       [IN] DER 编码的公钥，对端公钥
 * @param uiPublicKeyLen     [IN] DER 编码的公钥长度，对端公钥长度
 * @param pucInData          [IN] 待加密数据
 * @param uiInDataLen        [IN] 待加密数据长度
 * @param pucData            [OUT] 密文数据
 * @param puiDataLen         [IN/OUT] 输入时候表示缓冲区长度，输出表示密文长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_EccEncrypt(
        unsigned char *pucPublicKey,
        unsigned int uiPublicKeyLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int  *puiDataLen);

/**
 * @brief 通过证书 Ecc 加密
 *
 * @param hAppHandle         [IN] 应用接口句柄
 * @param pucCertificate     [IN] DER 编码的数字证书，对方证书
 * @param uiCertificateLen   [IN] DER 编码的数字证书长度，对方证书
 * @param pucInData          [IN] 待加密数据
 * @param uiInDataLen        [IN] 待加密数据长度
 * @param pucData            [OUT] 密文数据
 * @param puiDataLen         [IN/OUT] 输入时候表示缓冲区长度，输出表示密文长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_EccEncryptByCert(
        unsigned char *pucCertificate,
        unsigned int uiCertificateLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int *puiDataLen);

/**
 * @brief Ecc 解密
 *
 * @param hAppHandle         [IN] 应用接口句柄
 * @param pucContainerName   [IN] 容器名称
 * @param uiContainerNameLen [IN] 容器名称长度
 * @param pucPin             [IN] 设备口令
 * @param uiPinLen           [IN] 设备口令长度
 * @param pucInData          [IN] 待解密数据，带解密数据格式为: 04 + 公钥 + 密文
 * @param uiInDataLen        [IN] 待解密数据长度
 * @param pucData            [OUT] 明文数据
 * @param puiDataLen         [IN/OUT] 输入时候表示缓冲区长度，输出表示明文数据长度
 * @return 0 成功 / 非 0 失败，返回错误码
 */
CY_EXPORT int
CY_EccDecrypt(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int *puiDataLen);

/**
 * 生成 SM9系统密钥对
 *
 * @param uiMasterKeyType       [IN]    密钥类型 0 签名密钥对 1 加密密钥对
 * @param pucMasterPublicKey    [OUT]  系统主公钥
 * @param uiMasterPublicKeyLen  [OUT]  系统主公钥长度
 * @param pucMasterPrivateKey   [OUT]  系统主私钥
 * @param uiMasterPrivateKeyLen [OUT]  系统主私钥长度
 * @return 0 成功 / 非 0 失败，返回错误码。
 */
CY_EXPORT int
CY_GenSM9MasterKeyPair(
        unsigned int uiMasterKeyType,
        unsigned char *pucMasterPublicKey,
        unsigned int *uiMasterPublicKeyLen,
        unsigned char *pucMasterPrivateKey,
        unsigned int *uiMasterPrivateKeyLen);

/**
 * 生成 SM9用户密钥对
 *
 * @param uiMasterKeyType          [IN] 密钥类型 0 签名密钥对 1 加密密钥对
 * @param pucMasterPrivateKey      [IN] 系统主私钥
 * @param uiMasterPrivateKeyLen    [IN] 系统主私钥长度
 * @param pucUserID                [IN] 用户标识
 * @param uiUserIDLen              [IN] 用户标识长度
 * @param pucUserPrivateKey        [OUT]用户私钥
 * @param uiUserPrivateKeyLen      [OUT]用户私钥长度
 * @return 0 成功 / 非 0 失败，返回错误码。
 */
CY_EXPORT int
CY_GenSM9UserKeyPair(
        unsigned int  uiMasterKeyType,
        unsigned char *pucMasterPrivateKey,
        unsigned int uiMasterPrivateKeyLen,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        unsigned char *pucUserPrivateKey,
        unsigned int *uiUserPrivateKeyLen);

/**
 * SM9 签名
 *
 * @param pucMasterPublicKey      [IN] 系统签名主公钥
 * @param uiMasterPublicKeyLen    [IN] 系统签名主公钥长度
 * @param pucUserPrivateKey       [IN] 用户私钥
 * @param uiUserPrivateKeyLen     [IN] 用户私钥长度
 * @param pucInData               [IN]原始数据
 * @param uiInDataLen             [IN]原始数据长度
 * @param pucSignature            [OUT]签名值
 * @param puiSignatureLen         [IN/OUT]输入时候表示签名缓冲区长度，输出表示签名内容长度
 * @return 0 成功 / 非 0 失败，返回错误码。
 */
CY_EXPORT int
CY_SM9Sign(
        unsigned char *pucMasterPublicKey,
        unsigned int uiMasterPublicKeyLen,
        unsigned char *pucUserPrivateKey,
        unsigned int uiUserPrivateKeyLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen);

/**
 * SM9验证签名运算
 *
 * @param pucMasterPublicKey      [IN] 系统签名主公钥
 * @param uiMasterPublicKeyLen    [IN] 系统签名主公钥长度
 * @param pucUserID               [IN] 用户标识
 * @param uiUserIDLen             [IN] 用户标识长度
 * @param pucInData               [IN]原始数据
 * @param uiInDataLen             [IN]原始数据长度
 * @param pucSignature            [IN]签名值
 * @param puiSignatureLen         [IN]输入时候表示签名缓冲区长度，输出表示签名内容长度
 * @return 0 成功 / 非 0 失败，返回错误码。
 */
CY_EXPORT int
CY_SM9VerifySign(
        unsigned char *pucMasterPublicKey,
        unsigned int uiMasterPublicKeyLen,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignData,
        unsigned int uiSignDataLen);
/**
 * SM9加密
 *
 * @param pucMasterPublicKey      [IN] 系统签名主公钥
 * @param uiMasterPublicKeyLen    [IN] 系统签名主公钥长度
 * @param pucUserID               [IN] 用户标识
 * @param uiUserIDLen             [IN] 用户标识长度
 * @param pucInData               [IN] 待加密数据
 * @param uiInDataLen             [IN] 待加密数据长度
 * @param pucData                 [IN] 密文数据
 * @param puiDataLen              [IN] 输入时候表示缓冲区长度，输出表示密文长度
 * @return 0 成功 / 非 0 失败，返回错误码。
 */
CY_EXPORT int
CY_SM9Encrypt(
        unsigned char *pucMasterPublicKey,
        unsigned int uiMasterPublicKeyLen,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int  *puiDataLen);

/**
 * SM9解密
 *
 * @param pucUserPrivateKey       [IN] 用户私钥
 * @param uiUserPrivateKeyLen     [IN] 用户私钥长度
 * @param pucUserID               [IN] 用户标识
 * @param uiUserIDLen             [IN] 用户标识长度
 * @param pucInData               [IN]待解密数据
 * @param uiInDataLen             [IN]待解密数据长度
 * @param pucData                 [OUT]明文数据
 * @param puiDataLen              [IN/OUT]输入时候表示缓冲区长度，输出表示明文长度
 * @return 0 成功 / 非 0 失败，返回错误码。
 */
CY_EXPORT int
CY_SM9Decrypt(
        unsigned char *pucUserPrivateKey,
        unsigned int uiUserPrivateKeyLen,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int *puiDataLen);

/**
 * 无证书/隐式证书生成系统主密钥对（KGC接口）
 *
 * @param pucMasterPublicKey    [OUT]  系统主公钥
 * @param uiMasterPublicKeyLen  [OUT]  系统主公钥长度
 * @param pucMasterPrivateKey   [OUT]  系统主私钥(ms)
 * @param uiMasterPrivateKeyLen [OUT]  系统主私钥长度
 * @return 0 成功 / 非 0 失败，返回错误码。
 */
CY_EXPORT int CY_CLPKCGenMasterKeyPair(
                        unsigned char *pucMasterPublicKey,
                        unsigned int *uiMasterPublicKeyLen,
                        unsigned char *pucMasterPrivateKey,
                        unsigned int *uiMasterPrivateKeyLen);
/**
 * 无证书/隐式证书生成用户部分密钥对
 *
 * @param pucPartPublicKey         [OUT] 用户部分公钥（UA）
 * @param uiPartPublicKeyLen       [OUT] 用户部分公钥长度
 * @param pucPartPrivateKey        [OUT] 用户部分私钥（d'A）
 * @param uiPartPrivateKeyLen      [OUT] 用户部分私钥长度
 * @return 0 成功 / 非 0 失败，返回错误码。
 */                        
CY_EXPORT int CY_CLPKCGenUserPartKeyPair(
                                unsigned char *pucPartPublicKey,
                                unsigned int *uiPartPublicKeyLen,
                                unsigned char *pucPartPrivateKey,
                                unsigned int *uiPartPrivateKeyLen);
/**
 * 无证书/隐式证书生成用户密钥还原数据（KGC接口）
 *
 * @param pucMasterPublicKey            [IN] 系统主公钥（Ppub）
 * @param uiMasterPublicKeyLen          [IN] 系统主公钥长度
 * @param pucMasterPrivateKey           [IN] 系统主私钥(ms)
 * @param uiMasterPrivateKeyLen         [IN] 系统主私钥长度
 * @param pucPartPublicKey              [IN] 用户部分公钥（UA）
 * @param uiPartPublicKeyLen            [IN] 用户部分公钥长度
 * @param pucUserID                     [IN] 用户标识
 * @param uiUserIDLen                   [IN] 用户标识长度
 * @param pucKeyReconstructionDataTa    [OUT] 用户私钥还原数据（tA）
 * @param uiKeyReconstructionDataTaLen  [OUT] 用户私钥还原数据长度
 * @param pucKeyReconstructionDataWa    [OUT] 用户公钥还原数据（WA）
 * @param uiKeyReconstructionDataWaLen  [OUT] 用户公钥还原数据长度
 * @return 0 成功 / 非 0 失败，返回错误码。
 */    
CY_EXPORT int CY_CLPKCGenUserKeyReconstructionData(
                                        unsigned char *pucMasterPublicKey,
                                        unsigned int uiMasterPublicKeyLen,
                                        unsigned char *pucMasterPrivateKey,
                                        unsigned int uiMasterPrivateKeyLen,
                                        unsigned char *pucPartPublicKey,
                                        unsigned int uiPartPublicKeyLen,
                                        unsigned char *pucUserID,
                                        unsigned int uiUserIDLen,
                                        unsigned char *pucKeyReconstructionDataTa,
                                        unsigned int *uiKeyReconstructionDataTaLen,
                                        unsigned char *pucKeyReconstructionDataWa,
                                        unsigned int *uiKeyReconstructionDataWaLen);

/**
 * 无证书/隐式证书生成用户密钥对
 *
 * @param pucKeyReconstructionDataTa    [IN] 用户私钥还原数据（tA）
 * @param pucKeyReconstructionDataTaLen [IN] 用户私钥还原数据长度
 * @param pucKeyReconstructionDataWa    [IN] 用户公钥还原数据（WA）
 * @param pucKeyReconstructionDataWaLen [IN] 用户公钥还原数据长度
 * @param pucPartPrivateKey             [IN] 用户部分私钥（d'A）
 * @param uiPartPrivateKeyLen           [IN] 用户部分私钥长度
 * @param pucUserID                     [IN] 用户标识
 * @param uiUserIDLen                   [IN] 用户标识长度
 * @param pucMasterPublicKey            [IN] 系统主公钥（Ppub）
 * @param uiMasterPublicKeyLen          [IN] 系统主公钥长度
 * @param pucUserPrivateKey             [OUT] 用户私钥（dA）
 * @param uuiUserPrivateKeyLen          [OUT] 用户私钥长度
 * @return 0 成功 / 非 0 失败，返回错误码。
 */  
CY_EXPORT int CY_CLPKCGenUserKeyPair(
        unsigned char *pucKeyReconstructionDataTa,
        unsigned int uiKeyReconstructionDataTaLen,
        unsigned char *pucKeyReconstructionDataWa,
        unsigned int uiKeyReconstructionDataWaLen,
        unsigned char *pucPartPrivateKey,
        unsigned int uiPartPrivateKeyLen,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        unsigned char *pucMasterPublicKey,
        unsigned int uiMasterPublicKeyLen,
        unsigned char *pucUserPrivateKey,
        unsigned int *uiUserPrivateKeyLen);
/**
 * 无证书/隐式证书 签名运算
 * @param pucMasterPublicKey            [IN] 系统主公钥（Ppub）
 * @param uiMasterPublicKeyLen          [IN] 系统主公钥长度
 * @param pucUserPrivateKey    [IN] 用户私钥
 * @param uiUserPrivateKeyLen  [IN] 用户私钥长度
 * @param pucUserID                     [IN] 用户标识
 * @param uiUserIDLen                   [IN] 用户标识长度
 * @param pucKeyReconstructionDataWa    [IN] 用户公钥还原数据（WA）
 * @param uiKeyReconstructionDataWaLen [IN] 用户公钥还原数据长度
 * @param pucExtendedMessage   [IN] 扩展消息数据（无证书时，传入的是xWA‖yWA‖M；隐式证书时，传入的是ICA‖M）
 * @param uiExtendedMessageLen [IN] 扩展消息长度
 * @param pucSignature         [OUT] 签名值
 * @param puiSignatureLen      [IN/OUT] 输入时表示签名缓冲区长度，输出时表示签名内容长度
 * @return 0 成功 / 非 0 失败，返回错误码。
 */  
CY_EXPORT int CY_CLPKCSign(
        unsigned char *pucMasterPublicKey,
        unsigned int uiMasterPublicKeyLen,
        unsigned char *pucUserPrivateKey,
        unsigned int uiUserPrivateKeyLen,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        unsigned char *pucKeyReconstructionDataWa,
        unsigned int uiKeyReconstructionDataWaLen,
        unsigned char *pucExtendedMessage,
        unsigned int uiExtendedMessageLen,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen);
/**
 * 无证书/隐式证书验证签名运算
 *
 * @param pucMasterPublicKey        [IN] 系统主公钥（Ppub）
 * @param uiMasterPublicKeyLen      [IN] 系统主公钥长度
 * @param pucUserID                 [IN] 用户标识
 * @param uiUserIDLen               [IN] 用户标识长度
 * @param pucKeyReconstructionDataWa [IN] 用户公钥还原数据（WA）
 * @param uiKeyReconstructionDataWaLen [IN] 用户公钥还原数据长度
 * @param pucHashZa                 [IN] 杂凑值ZA（无证书时，传入的是HA；隐式证书时，传入的是空字符串）
 * @param uiHashZaLen               [IN] 杂凑值ZA长度
 * @param pucExtendedMessage        [IN] 扩展消息数据（无证书时，传入的是xWA‖yWA‖M；隐式证书时，传入的是ICA‖M）
 * @param uiExtendedMessageLen      [IN] 扩展消息长度
 * @param pucSignData               [IN] 签名值
 * @param uiSignDataLen             [IN] 签名值长度
 * @return 0 成功 / 非 0 失败，返回错误码。
 */
CY_EXPORT int CY_CLPKCVerifySign(
        unsigned char *pucMasterPublicKey,
        unsigned int uiMasterPublicKeyLen,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        unsigned char *pucKeyReconstructionDataWa,
        unsigned int uiKeyReconstructionDataWaLen,
        unsigned char *pucExtendedMessage,
        unsigned int uiExtendedMessageLen,
        unsigned char *pucSignData,
        unsigned int uiSignDataLen);
/**
 * 无证书/隐式证书加密
 *
 * @param pucMasterPublicKey        [IN] 系统主公钥（Ppub）
 * @param uiMasterPublicKeyLen      [IN] 系统主公钥长度
 * @param pucUserID                 [IN] 用户标识
 * @param uiUserIDLen               [IN] 用户标识长度
 * @param pucKeyReconstructionDataWa [IN] 用户公钥还原数据（WA）
 * @param uiKeyReconstructionDataWaLen [IN] 用户公钥还原数据长度
 * @param pucInData                 [IN] 待加密数据
 * @param uiInDataLen               [IN] 待加密数据长度
 * @param pucData                   [OUT] 密文数据
 * @param puiDataLen                [IN/OUT] 输入时表示缓冲区长度，输出时表示密文长度
 * @return 0 成功 / 非 0 失败，返回错误码。
 */
CY_EXPORT int CY_CLPKCEncrypt(
        unsigned char *pucMasterPublicKey,
        unsigned int uiMasterPublicKeyLen,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        unsigned char *pucKeyReconstructionDataWa,
        unsigned int uiKeyReconstructionDataWaLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int  *puiDataLen);

/**
 * 无证书/隐式证书解密服务
 *
 * @param pucUserPrivateKey    [IN] 用户私钥
 * @param uiUserPrivateKeyLen  [IN] 用户私钥长度
 * @param pucInData           [IN] 待解密数据
 * @param uiInDataLen         [IN] 待解密数据长度
 * @param pucData             [OUT] 解密后的数据
 * @param puiDataLen          [IN/OUT] 输入时表示缓冲区长度，输出时表示解密数据长度
 * @return 0 成功 / 非 0 失败，返回错误码。
 */
CY_EXPORT int CY_CLPKCDecrypt(
        unsigned char *pucUserPrivateKey,
        unsigned int uiUserPrivateKeyLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int *puiDataLen);

/**
 * 创建对称算法对象
 *
 * @param phSymmKeyObj      [OUT] 对称算法对象
 * @param pucKey            [IN]  对称密钥
 * @param uiKeyLen          [IN]  对称密钥长度
 * @param pucIV             [IN]  初始向量
 * @param uiIVLen           [IN]  初始向量长度
 * @param uiEncOrDec        [IN]  1 加密，0 解密
 * @param uiCryptoAlgoType  [IN]  分组密码标识
 * @return 0 成功 / 非 0 失败，返回错误码。
 */
CY_EXPORT int
CY_CreateSymmKeyObj(
        void **phSymmKeyObj,
        unsigned char *pucKey,
        unsigned int uiKeyLen,
        unsigned char *pucIV,
        unsigned int uiIVLen,
        unsigned int uiEncOrDec,
        unsigned int uiCryptoAlgoType);

/**
 * 销毁对称算法对象
 *
 * @param hSymmKeyObj   [IN]  对称算法对象
 * @return 0 成功，非 0 失败。
 */
CY_EXPORT int
CY_DestroySymmKeyObj(
        void *hSymmKeyObj);

/**
 * 单块加密运算
 *
 * @param hSymmKeyObj   [IN]  对称算法对象
 * @param pucInData     [IN]  输入数据
 * @param uiInDataLen   [IN]  输入数据长度
 * @param pucOutData    [OUT] 输出数据
 * @param puiOutDataLen [IN/OUT] 输入时候表示缓冲区长度，输出表示输出数据长度
 * @return 0 成功 / 非 0 失败，返回错误码。
 */
CY_EXPORT int
CY_SymmEncrypt(
        void *hSymmKeyObj,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen);

/**
 * 多块加密运算
 *
 * @param hSymmKeyObj   [IN]  对称算法对象
 * @param pucInData     [IN]  输入数据
 * @param uiInDataLen   [IN]  输入数据长度
 * @param pucOutData    [OUT] 输出数据
 * @param puiOutDataLen [IN/OUT] 输入时候表示缓冲区长度，输出表示输出数据长度
 * @return 0 成功 / 非 0 失败，返回错误码。
 */
CY_EXPORT int
CY_SymmEncryptUpdate(
        void *hSymmKeyObj,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen);

/**
 * 结束加密运算
 *
 * @param hSymmKeyObj   [IN]  对称算法对象
 * @param pucOutData    [OUT] 输出数据
 * @param puiOutDataLen [IN/OUT] 输入时候表示缓冲区长度，输出表示输出数据长度
 * @return 0 成功，非 0 失败。
 */
CY_EXPORT int
CY_SymmEncryptFinal(
        void *hSymmKeyObj,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen);

/**
 * 单块解密运算
 *
 * @param hSymmKeyObj   [IN]  对称算法对象
 * @param pucInData     [IN]  输入数据
 * @param uiInDataLen   [IN]  输入数据长度
 * @param pucOutData    [OUT] 输出数据
 * @param puiOutDataLen [IN/OUT] 输入时候表示缓冲区长度，输出表示输出数据长度
 * @return 0 成功 / 非 0 失败，返回错误码。
 */
CY_EXPORT int
CY_SymmDecrypt(
        void *hSymmKeyObj,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen);

/**
 * 多块解密运算
 *
 * @param hSymmKeyObj   [IN]  对称算法对象
 * @param pucInData     [IN]  输入数据
 * @param uiInDataLen   [IN]  输入数据长度
 * @param pucOutData    [OUT] 输出数据
 * @param puiOutDataLen [IN/OUT] 输入时候表示缓冲区长度，输出表示输出数据长度
 * @return 0 成功 / 非 0 失败，返回错误码。
 */
CY_EXPORT int
CY_SymmDecryptUpdate(
        void *hSymmKeyObj,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen);

/**
 * 结束解密运算
 *
 * @param hSymmKeyObj   [IN]  对称算法对象
 * @param pucOutData    [OUT] 输出数据
 * @param puiOutDataLen [IN/OUT] 输入时候表示缓冲区长度，输出表示输出数据长度
 * @return 0 成功 / 非 0 失败，返回错误码。
 */
CY_EXPORT int
CY_SymmDecryptFinal(
        void *hSymmKeyObj,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen);

/**
 * @brief Hmac 计算
 * @param uiHashAlgoType [IN]  哈希算法标识
 * @param keyData        [IN]  密钥
 * @param keyDataLen     [IN]  密钥长度
 * @param pucInData      [IN]  输入数据
 * @param uiInDataLen    [IN]  输入数据长度
 * @param pucOutData     [OUT] 输出数据
 * @param puiOutDataLen  [IN/OUT] 输入时候表示缓冲区长度，输出表示输出数据长度
 * @return 0 成功 / 非 0 失败，返回错误码。
 */
CY_EXPORT int
CY_Hmac(unsigned int uiHashAlgoType,
        unsigned char *pucKey,
        unsigned int uiKeyLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucOutData,
        unsigned int *puiOutDataLen);

/**
 * @brief HKdf 计算
 *
 * @param uiHashAlgoType [IN]  哈希算法标识
 * @param pucIKM         [IN]  原始密钥
 * @param uiIKMLen       [IN]  原始密钥长度
 * @param pucSaltData    [IN]  如为空则为初始化为 0 的字符串，长度为哈希函数的散列值长度。
 * @param uiSaltDataLen  [IN]  随机源长度
 * @param pucInData      [IN]  输入数据
 * @param uiInDataLen    [IN]  输入数据长度
 * @param pucOutData     [OUT] 输出数据
 * @param puiOutDataLen  [IN]  输出数据长度
 * @return 0 成功 / 非 0 失败，返回错误码。
 */
CY_EXPORT int
CY_Hkdf(unsigned int uiHashAlgoType,
        unsigned char *pucIkm,
        unsigned int uiIkmLen,
        unsigned char *pucSaltData,
        unsigned int uiSaltDataLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucOutData,
        unsigned int puiOutDataLen);

#ifdef __cpulsplus
}
#endif


#endif //SCM_CYBER_PKI_H
