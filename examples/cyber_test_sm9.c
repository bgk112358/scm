// Create by Gerryfan
// Copyright 2025 China Automotive Research Software Evaluating Co., Ltd.
//

#include <stdio.h>
#include <string.h>

#include "cyber_pki.h"
#include "cyber_error.h"

int SM9_sign_test(void)
{
    printf("SM9 sign test\n");
    int ret = 0;
    unsigned char pucMasterPublicKey[129] = {0};
    unsigned int uiMasterPublicKeyLen = 0;
    unsigned char pucMasterPrivateKey[128] = {0};
    unsigned int uiMasterPrivateKeyLen = 0;
    unsigned int uiMasterKeyType = 0;
    unsigned char *msg = "Chinese IBS standard";
    unsigned int msg_len = strlen((char *)msg);
    unsigned char sign[256] = {0};
    unsigned int sign_len = 256;
    ret = CY_GenSM9MasterKeyPair(uiMasterKeyType,  pucMasterPublicKey, &uiMasterPublicKeyLen,  pucMasterPrivateKey, &uiMasterPrivateKeyLen);
    if(ret != 0){
        printf("CY_GenSM9MasterKeyPair failed, ret = %d\n", ret);
        return ret;
    }
    printf("CY_GenSM9MasterKeyPair success, uiMasterPublicKeyLen = %d, uiMasterPrivateKeyLen = %d\n", uiMasterPublicKeyLen, uiMasterPrivateKeyLen);

    unsigned char pucUserPrivateKey[128] = {0};
    unsigned int  uiUserPrivateKeyLen = 0;
    unsigned char *pucUserID = "Alice";
    unsigned int uiUserIDLen = strlen((char *)pucUserID);

    ret = CY_GenSM9UserKeyPair(uiMasterKeyType, pucMasterPrivateKey, uiMasterPrivateKeyLen, pucUserID, uiUserIDLen, pucUserPrivateKey, &uiUserPrivateKeyLen);
    if(ret != 0){
        printf("CY_GenSM9UserKeyPair failed, ret = %d\n", ret);
        return ret;
    }
    printf("CY_GenSM9UserKeyPair success, uiUserPrivateKeyLen = %d\n", uiUserPrivateKeyLen);

    ret = CY_SM9Sign(pucMasterPublicKey, uiMasterPublicKeyLen, pucUserPrivateKey, uiUserPrivateKeyLen,msg, msg_len, sign, &sign_len);
    if(ret != 0){
        printf("CY_SM9Sign failed, ret = %d\n", ret);
        return ret;
    }
    printf("CY_SM9Sign success, sign_len = %d\n", sign_len);
    
    ret = CY_SM9VerifySign(
        pucMasterPublicKey,
        uiMasterPublicKeyLen,
        pucUserID,
        uiUserIDLen,
        msg,
        msg_len,
        sign,
        sign_len);
    if(ret != 0){
        printf("CY_SM9Verify failed, ret = %d\n", ret);
        return ret;
    }
    printf("CY_SM9Verify success\n");
    return 0;
}
int SM9_encrypt_test(void)
{
    printf("SM9 encrypt test\n");
    int ret = 0;
    unsigned char pucMasterPublicKey[129] = {0};
    unsigned int uiMasterPublicKeyLen = 0;
    unsigned char pucMasterPrivateKey[129] = {0};
    unsigned int uiMasterPrivateKeyLen = 0;
    unsigned int uiMasterKeyType = 1;
    unsigned char *msg = "Chinese IBS standard";
    unsigned int msg_len = strlen((char *)msg);
    unsigned char cipher[256] = {0};
    unsigned int cipher_len = 256;
    unsigned char plain[256] = {0};
    unsigned int plain_len = 256;
    ret = CY_GenSM9MasterKeyPair(uiMasterKeyType,  pucMasterPublicKey, &uiMasterPublicKeyLen,  pucMasterPrivateKey, &uiMasterPrivateKeyLen);
    if(ret != 0){
        printf("CY_GenSM9MasterKeyPair failed, ret = %d\n", ret);
        return ret;
    }
    printf("CY_GenSM9MasterKeyPair success, uiMasterPublicKeyLen = %d, uiMasterPrivateKeyLen = %d\n", uiMasterPublicKeyLen, uiMasterPrivateKeyLen);

    unsigned char pucUserPrivateKey[129] = {0};
    unsigned int  uiUserPrivateKeyLen = 0;
    unsigned char *pucUserID = "Alice";
    unsigned int uiUserIDLen = strlen((char *)pucUserID);

    ret = CY_GenSM9UserKeyPair(uiMasterKeyType, pucMasterPrivateKey, uiMasterPrivateKeyLen, pucUserID, uiUserIDLen, pucUserPrivateKey, &uiUserPrivateKeyLen);
    if(ret != 0){
        printf("CY_GenSM9UserKeyPair failed, ret = %d\n", ret);
        return ret;
    }
    printf("CY_GenSM9UserKeyPair success, uiUserPrivateKeyLen = %d\n", uiUserPrivateKeyLen);

    ret = CY_SM9Encrypt(pucMasterPublicKey, uiMasterPublicKeyLen, pucUserID, uiUserIDLen,msg, msg_len, cipher, &cipher_len);
    if(ret != 0){
        printf("CY_SM9Encrypt failed, ret = %d\n", ret);
        return ret;
    }
    printf("CY_SM9Encrypt success, cipher_len = %d\n", cipher_len);

    ret = CY_SM9Decrypt(
        pucUserPrivateKey,
        uiUserPrivateKeyLen,
        pucUserID, 
        uiUserIDLen,
        cipher,
        cipher_len,
        plain,
        &plain_len);
    if(ret != 0) {
        printf("CY_SM9Decrypt failed, ret = %d\n", ret);
        return ret;
    }
    printf("CY_SM9Decrypt success len is %d data is %s\n", plain_len, plain);
    return 0;
}
int main(int argc, char *argv[])
{
    SM9_sign_test();
    SM9_encrypt_test();
    return 0;
}