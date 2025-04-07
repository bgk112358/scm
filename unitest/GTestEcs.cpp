// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "gtest/gtest.h"
#include <cstring>
extern "C" {
#include "cyber_pki.h"
}

TEST(EcsTest, Ecs) {
    void *hAppHandle = nullptr;
    const char *pcUserId = "test@example.com";
    int rv = CY_InitService(&hAppHandle,
                            "./cyber");
    EXPECT_EQ(rv, CY_R_SUCCESS);
    unsigned char ucMasterPublicKey[128] = {0};
    unsigned int  uiMasterPublicKeyLen = 128;
    unsigned char ucMasterPrivateKey[128] = {0};
    unsigned int  uiMasterPrivateKeyLen = 128;
    rv = CY_CLPKCGenMasterKeyPair(
            ucMasterPublicKey,
            &uiMasterPublicKeyLen,
            ucMasterPrivateKey,
            &uiMasterPrivateKeyLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    unsigned char ucUserPartPublicKey[128] = {0};
    unsigned int  uiUserPartPublicKeyLen = 128;
    unsigned char ucUserPartPrivateKey[128] = {0};
    unsigned int  uiUserPartPrivateKeyLen = 128;
    rv = CY_CLPKCGenUserPartKeyPair(
            ucUserPartPublicKey,
            &uiUserPartPublicKeyLen,
            ucUserPartPrivateKey,
            &uiUserPartPrivateKeyLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    unsigned char ucKeyReconstructionDataTa[1024] = {0};
    unsigned int uiKeyReconstructionDataTaLen     = 1024;
    unsigned char ucKeyReconstructionDataWa[1024] = {0};
    unsigned int uiKeyReconstructionDataWaLen     = 1024;
    rv = CY_CLPKCGenUserKeyReconstructionData(
            ucMasterPublicKey,
            uiMasterPublicKeyLen,
            ucMasterPrivateKey,
            uiMasterPrivateKeyLen,
            ucUserPartPublicKey,
            uiUserPartPublicKeyLen,
            (unsigned char *)pcUserId,
            strlen(pcUserId),
            ucKeyReconstructionDataTa,
            &uiKeyReconstructionDataTaLen,
            ucKeyReconstructionDataWa,
            &uiKeyReconstructionDataWaLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    unsigned char ucUserPrivateKey[1024] = {0};
    unsigned int uiUserPrivateKeyLen     = 1024;
    rv = CY_CLPKCGenUserKeyPair(
            ucKeyReconstructionDataTa,
            uiKeyReconstructionDataTaLen,
            ucKeyReconstructionDataWa,
            uiKeyReconstructionDataWaLen,
            ucUserPartPrivateKey,
            uiUserPartPrivateKeyLen,
            (unsigned char *)pcUserId,
            strlen(pcUserId),
            ucMasterPublicKey,
            uiMasterPublicKeyLen,
            ucUserPrivateKey,
            &uiUserPrivateKeyLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    unsigned char ucInData[] = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    unsigned char ucSignature[1024] = {0};
    unsigned int uiSignatureLen = 1024;
    rv = CY_CLPKCSign(
            ucMasterPublicKey,
            uiMasterPublicKeyLen,
            ucUserPrivateKey,
            uiUserPrivateKeyLen,
            (unsigned char *)pcUserId,
            strlen(pcUserId),
            ucKeyReconstructionDataWa,
            uiKeyReconstructionDataWaLen,
            ucInData,
            sizeof(ucInData),
            ucSignature,
            &uiSignatureLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    rv = CY_CLPKCVerifySign(
            ucMasterPublicKey,
            uiMasterPublicKeyLen,
            (unsigned char *)pcUserId,
            strlen(pcUserId),
            ucKeyReconstructionDataWa,
            uiKeyReconstructionDataWaLen,
            ucInData,
            sizeof(ucInData),
            ucSignature,
            uiSignatureLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);

    rv = CY_Finalize(hAppHandle);
    EXPECT_EQ(rv, 0);
    hAppHandle = nullptr;
}