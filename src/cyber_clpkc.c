//
// Create by Gerryfan on 2025/02/27
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "crypto/clpkc/clpkc.h"

/**
 * 无证书/隐式证书生成系统主密钥对（KGC接口）
 *
 * @param pucMasterPublicKey    [OUT]  系统主公钥
 * @param uiMasterPublicKeyLen  [OUT]  系统主公钥长度
 * @param pucMasterPrivateKey   [OUT]  系统主私钥(ms)
 * @param uiMasterPrivateKeyLen [OUT]  系统主私钥长度
 * @return 0 成功 / 非 0 失败，返回错误码。
 */
int CY_CLPKCGenMasterKeyPair(
                        unsigned char *pucMasterPublicKey,
                        unsigned int *uiMasterPublicKeyLen,
                        unsigned char *pucMasterPrivateKey,
                        unsigned int *uiMasterPrivateKeyLen)
{
    return GenCLPKCMasterKey(pucMasterPrivateKey, uiMasterPrivateKeyLen, pucMasterPublicKey, uiMasterPublicKeyLen);    
}
/**
 * 无证书/隐式证书生成用户部分密钥对
 *
 * @param pucPartPublicKey         [OUT] 用户部分公钥（UA）
 * @param uiPartPublicKeyLen       [OUT] 用户部分公钥长度
 * @param pucPartPrivateKey        [OUT] 用户部分私钥（d'A）
 * @param uiPartPrivateKeyLen      [OUT] 用户部分私钥长度
 * @return 0 成功 / 非 0 失败，返回错误码。
 */                        
int CY_CLPKCGenUserPartKeyPair(
                                unsigned char *pucPartPublicKey,
                                unsigned int *uiPartPublicKeyLen,
                                unsigned char *pucPartPrivateKey,
                                unsigned int *uiPartPrivateKeyLen)
{
    return GenUAINFO(pucPartPrivateKey, uiPartPrivateKeyLen, pucPartPublicKey, uiPartPublicKeyLen);
}
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
int CY_CLPKCGenUserKeyReconstructionData(
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
                                        unsigned int *uiKeyReconstructionDataWaLen)
{
    int ret = 0;
    unsigned char HA[32] = {0};
    int HALen = 32;
    ret  = CalHAINFO(pucUserID, uiUserIDLen,pucMasterPublicKey, uiMasterPublicKeyLen, HA, &HALen);
    if(ret != 0)
    {
        MC_LOG_ERR("CalHAINFO failed, ret = %d\n", ret);
        return ret;
    }
    unsigned char WA[64] = {0};
    int WA_len = 64;
    unsigned char w[32]; 
    int wLen = 32;
    ret = CalWAInfo(pucPartPublicKey, uiPartPublicKeyLen, WA,&WA_len, w, &wLen);
    if(ret != 0)
    {
        MC_LOG_ERR("CalWAInfo failed, ret = %d\n", ret);
        return ret;
    }
    unsigned char lamda[32] = {0};
    int lamda_len = 32;
    ret = CalLamdaInfo(WA, WA_len, HA, HALen, lamda, &lamda_len);
    if(ret != 0)
    {
        MC_LOG_ERR("cal lamada failed\n");
        return ret;
    }
    unsigned char tA[32] = {0};
    int tALen = 32;
    //K5：KGC计算tA=(w + λ*ms) mod n，并KGC向用户A返回tA和WA；
    ret = CaltAInfo(w, wLen, lamda, lamda_len, pucMasterPrivateKey, uiMasterPrivateKeyLen, tA, &tALen);
    if(ret != 0)
    {
        MC_LOG_ERR("cal tA failed\n");
        return ret;
    }
    memcpy(pucKeyReconstructionDataTa, tA, tALen);
    *uiKeyReconstructionDataTaLen = tALen;
    memcpy(pucKeyReconstructionDataWa, WA, WA_len);
    *uiKeyReconstructionDataWaLen = WA_len;

    return ret;
}

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
int CY_CLPKCGenUserKeyPair(
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
                            unsigned int *uiUserPrivateKeyLen)
{
    int ret = 0;
    unsigned char HA[32] = {0};
    unsigned int HALen = 32;
    ret = CalHAINFO(pucUserID, uiUserIDLen, pucMasterPublicKey, uiMasterPublicKeyLen, HA, &HALen);
    if(ret != 0)
    {
        MC_LOG_ERR("cal HAINFO failed\n");
        return ret;
    }
    unsigned char lamda[32] = {0};
    int lamda_len = 32;
    ret = CalLamdaInfo(pucKeyReconstructionDataWa, uiKeyReconstructionDataWaLen, HA, HALen, lamda, &lamda_len);
    if(ret != 0)
    {
        MC_LOG_ERR("cal lamada failed\n");
        return ret;
    }
    unsigned char PA[128] = {0};
    int PALen = 128;
    ret = CalPAInfo(pucKeyReconstructionDataWa, uiKeyReconstructionDataWaLen, lamda, lamda_len, 
                    pucMasterPublicKey, uiMasterPublicKeyLen, PA, &PALen);
    if(ret != 0)
    {
        MC_LOG_ERR("cal PA failed\n");
        return ret;
    }
    unsigned char dA[32] = {0};
    int dALen = 32;
    ret = CaldAValue(pucKeyReconstructionDataTa, uiKeyReconstructionDataTaLen, pucPartPrivateKey, uiPartPrivateKeyLen,dA, &dALen);
    if(ret != 0)
    {
        MC_LOG_ERR("cal dA failed\n");
        return ret;
    }
    unsigned char prePA[128] = {0};
    //6.4 A4: P'A=[dA]G；
    int prePALen = 128;
    ret = CalprePAInfo(dA, dALen, prePA, &prePALen);
    if(ret != 0)
    {
        MC_LOG_ERR("cal prePA failed\n");
        return ret;
    }
    if(memcmp(PA, prePA, PALen) != 0)
    {
        MC_LOG_ERR("PA is not equal to prePA\n");
        return -1;
    }
    memcpy(pucUserPrivateKey,dA, dALen);
    *uiUserPrivateKeyLen = dALen;
    return ret;
}
/**
 * 无证书/隐式证书 签名运算
 *
 * @param pucUserPrivateKey    [IN] 用户私钥
 * @param uiUserPrivateKeyLen  [IN] 用户私钥长度
 * @param pucHashZa            [IN] 杂凑值ZA（无证书时，传入的是HA；隐式证书时，传入的是空字符串）
 * @param uiHashZaLen          [IN] 杂凑值ZA长度
 * @param pucKeyReconstructionDataWa    [IN] 用户公钥还原数据（WA）
 * @param uiKeyReconstructionDataWaLen [IN] 用户公钥还原数据长度
 * @param pucExtendedMessage   [IN] 扩展消息数据（无证书时，传入的是xWA‖yWA‖M；隐式证书时，传入的是ICA‖M）
 * @param uiExtendedMessageLen [IN] 扩展消息长度
 * @param pucSignature         [OUT] 签名值
 * @param puiSignatureLen      [IN/OUT] 输入时表示签名缓冲区长度，输出时表示签名内容长度
 * @return 0 成功 / 非 0 失败，返回错误码。
 */  
int CY_CLPKCSign(
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
        unsigned int *puiSignatureLen)
{
    int ret = 0;
    unsigned char HA[32] = {0};
    unsigned int HALen = 32;
    ret = CalHAINFO(pucUserID, uiUserIDLen, pucMasterPublicKey, uiMasterPublicKeyLen, HA, &HALen);
    if(ret != 0)
    {
        MC_LOG_ERR("cal HAINFO failed\n");
        return ret;
    }
    return CLPKC_Sign(pucExtendedMessage, uiExtendedMessageLen, HA, HALen, pucKeyReconstructionDataWa,
                uiKeyReconstructionDataWaLen, pucUserPrivateKey, uiUserPrivateKeyLen, pucSignature, puiSignatureLen);

}

/**
 * 无证书/隐式证书验证签名运算
 *
 * @param pucMasterPublicKey        [IN] 系统主公钥（Ppub）
 * @param uiMasterPublicKeyLen      [IN] 系统主公钥长度
 * @param pucUserID                 [IN] 用户标识
 * @param uiUserIDLen               [IN] 用户标识长度
 * @param pucKeyReconstructionDataWa [IN] 用户公钥还原数据（WA）
 * @param uiKeyReconstructionDataWaLen [IN] 用户公钥还原数据长度
 * @param pucExtendedMessage        [IN] 扩展消息数据（无证书时，传入的是xWA‖yWA‖M；隐式证书时，传入的是ICA‖M）
 * @param uiExtendedMessageLen      [IN] 扩展消息长度
 * @param pucSignData               [IN] 签名值
 * @param uiSignDataLen             [IN] 签名值长度
 * @return 0 成功 / 非 0 失败，返回错误码。
 */
int CY_CLPKCVerifySign(
        unsigned char *pucMasterPublicKey,
        unsigned int uiMasterPublicKeyLen,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        unsigned char *pucKeyReconstructionDataWa,
        unsigned int uiKeyReconstructionDataWaLen,
        unsigned char *pucExtendedMessage,
        unsigned int uiExtendedMessageLen,
        unsigned char *pucSignData,
        unsigned int uiSignDataLen)
{
    int ret = 0;
    unsigned char PA[128] = {0};
    int PALen = 128;
    unsigned char lamda[128] = {0};
    int lamdaLen = 128;

    unsigned char HA[32] = {0};
    unsigned int HALen = 32;
    ret = CalHAINFO(pucUserID, uiUserIDLen, pucMasterPublicKey, uiMasterPublicKeyLen, HA, &HALen);
    if(ret != 0)
    {
        MC_LOG_ERR("cal HAINFO failed\n");
        return ret;
    }

    ret = CalLamdaInfo(pucKeyReconstructionDataWa, uiKeyReconstructionDataWaLen, HA, HALen,lamda, &lamdaLen);
    if(ret != 0)
    {
        MC_LOG_ERR("CalLamdaInfo failed, ret = %d\n", ret);
        return ret;
    }
    ret = CalPAInfo(pucKeyReconstructionDataWa, uiKeyReconstructionDataWaLen,lamda,lamdaLen, 
                    pucMasterPublicKey, uiMasterPublicKeyLen, PA, &PALen);
    if(ret != 0)
    {
        MC_LOG_ERR("CalPAInfo failed, ret = %d\n", ret);
        return ret;
    }
    ret = CLPKC_Verify(PA, PALen, pucExtendedMessage, uiExtendedMessageLen, HA, HALen,
                        pucKeyReconstructionDataWa, uiKeyReconstructionDataWaLen, pucSignData, uiSignDataLen);
    return ret;
}
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
int CY_CLPKCEncrypt(
        unsigned char *pucMasterPublicKey,
        unsigned int uiMasterPublicKeyLen,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        unsigned char *pucKeyReconstructionDataWa,
        unsigned int uiKeyReconstructionDataWaLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int  *puiDataLen)
{
    int ret = 0;
    unsigned char PA[128] = {0};
    int PALen = 128;
    unsigned char lamda[128] = {0};
    int lamdaLen = 128;
    unsigned char HA[128] = {0};
    int HALen = 128;
    ret = CalHAINFO(pucUserID, uiUserIDLen, pucMasterPublicKey, uiMasterPublicKeyLen, HA, &HALen);
    if(ret != 0)
    {
        MC_LOG_ERR("CalHAINFO failed, ret = %d\n", ret);
        return ret;
    }
    ret = CalLamdaInfo(pucKeyReconstructionDataWa, uiKeyReconstructionDataWaLen, HA, HALen,lamda, &lamdaLen);
    if(ret != 0)
    {
        MC_LOG_ERR("CalLamdaInfo failed, ret = %d\n", ret);
        return ret;
    }
    ret = CalPAInfo(pucKeyReconstructionDataWa, uiKeyReconstructionDataWaLen,lamda,lamdaLen, 
                    pucMasterPublicKey, uiMasterPublicKeyLen, PA, &PALen);
    if(ret != 0)
    {
        MC_LOG_ERR("CalPAInfo failed, ret = %d\n", ret);
        return ret;
    }
    ret = CLPKC_Encrypt(PA, PALen, pucInData, uiInDataLen, pucData, puiDataLen);
    if(ret != 0)
    {
        MC_LOG_ERR("CLPKC_Encrypt failed, ret = %d\n", ret);
        return ret;
    }
    return ret;
}

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
int CY_CLPKCDecrypt(
        unsigned char *pucUserPrivateKey,
        unsigned int uiUserPrivateKeyLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int *puiDataLen)
{    
    int ret = 0;
    ret = CLPKC_Decrypt(pucUserPrivateKey, uiUserPrivateKeyLen, pucInData, uiInDataLen, pucData, puiDataLen);  
    return ret;  
}