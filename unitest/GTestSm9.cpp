// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "gtest/gtest.h"
#include <cstring>
extern "C" {
#include "cyber_pki.h"
}

TEST(SM9Test, SM9) {
    void *hAppHandle = nullptr;
    const char *pcUserId = "Alice@example.com";
    int rv = CY_InitService(&hAppHandle,
                            "./cyber");
    EXPECT_EQ(rv, CY_R_SUCCESS);
    unsigned char ucMasterPublicKey[128] = {0};
    unsigned int  uiMasterPublicKeyLen = 128;
    unsigned char ucMasterPrivateKey[128] = {0};
    unsigned int  uiMasterPrivateKeyLen = 128;
    rv = CY_GenSM9MasterKeyPair(
            0,
            ucMasterPublicKey,
            &uiMasterPublicKeyLen,
            ucMasterPrivateKey,
            &uiMasterPrivateKeyLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    unsigned char ucUserPrivateKey[128] = {0};
    unsigned int  uiUserPrivateKeyLen = 128;
    rv = CY_GenSM9UserKeyPair(
            0,
            ucMasterPrivateKey,
            uiMasterPrivateKeyLen,
            (unsigned char *)pcUserId,
            strlen(pcUserId),
            ucUserPrivateKey,
            &uiUserPrivateKeyLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    unsigned char ucInData[] = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    unsigned char ucSignature[1024] = {0};
    unsigned int uiSignatureLen = 1024;
    rv = CY_SM9Sign(ucMasterPublicKey,
                    uiMasterPublicKeyLen,
                    ucUserPrivateKey,
                    uiUserPrivateKeyLen,
                    ucInData,
                    sizeof(ucInData),
                    ucSignature,
                    &uiSignatureLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    rv = CY_SM9VerifySign(ucMasterPublicKey,
                          uiMasterPublicKeyLen,
                          (unsigned char *)pcUserId,
                          strlen(pcUserId),
                          ucInData,
                          sizeof(ucInData),
                          ucSignature,
                          uiSignatureLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);

    rv = CY_Finalize(hAppHandle);
    EXPECT_EQ(rv, 0);
    hAppHandle = nullptr;
}