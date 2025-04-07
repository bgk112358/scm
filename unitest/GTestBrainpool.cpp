//
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "gtest/gtest.h"
#include <cstring>
#include <fstream>
extern "C" {
#include "cyber_pki.h"
#include "cyber_error.h"
}

TEST(EccTest, Brainpool256r1) {
    void *hAppHandle = nullptr;
    const char *pcContainerName = "brainpool256";
    const char *pcPin = "brainpool256";
    int rv = CY_InitService(&hAppHandle, "./cyber");
    EXPECT_EQ(rv, 0);
    rv = CY_GenEccKeyPair(
            hAppHandle,
            (unsigned char *) pcContainerName,
            strlen(pcContainerName),
            (unsigned char *) pcPin,
            strlen(pcPin),
            SGD_BRAINPOOL_P256R1,
            SGD_KEYUSAGE_SIGN,
            1);
    EXPECT_EQ(rv, 0);
    unsigned char pucPublicKey[1024] = {0};
    unsigned int uiPublicKeyLen = 1024;
    rv = CY_GetEccPublicKey(
            hAppHandle,
            (unsigned char *) pcContainerName,
            strlen(pcContainerName),
            SGD_KEYUSAGE_SIGN,
            pucPublicKey,
            &uiPublicKeyLen);
    EXPECT_EQ(rv, 0);
    unsigned char ucInData[] = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    unsigned char ucSignature[1024] = {0};
    unsigned int uiSignatureLen = 1024;
    unsigned char ucSignature1[] = {
            0x30, 0x46, 0x02, 0x21, 0x00, 0x9a, 0xf8, 0x47, 0x4a, 0x7d, 0x3e, 0x11, 0x9a, 0xda, 0xba, 0xce,
            0x59, 0x48, 0x05, 0x9b, 0x76, 0x7b, 0x9c, 0x2e, 0x97, 0x95, 0x90, 0x42, 0xdb, 0x6c, 0x51, 0x61,
            0xdf, 0x9c, 0xd1, 0xcb, 0xa6, 0x02, 0x21, 0x00, 0xe4, 0xfb, 0x7c, 0xf2, 0x65, 0xbb, 0xe1, 0x7a,
            0x6a, 0xc0, 0xa5, 0x9e, 0xb1, 0x7a, 0x3e, 0x81, 0x3e, 0x06, 0xdb, 0xba, 0xc9, 0x35, 0xb1, 0x05,
            0xeb, 0x77, 0x5b, 0xc0, 0xb1, 0xd3, 0xc7, 0x4c
    };
    rv = CY_EccSign(
            hAppHandle,
            (unsigned char *) pcContainerName,
            strlen(pcContainerName),
            (unsigned char *) pcPin,
            strlen(pcPin),
            SGD_SHA512,
            ucInData,
            sizeof(ucInData),
            ucSignature,
            &uiSignatureLen);
    EXPECT_EQ(rv, 0);
    rv = CY_EccVerifySign(
            SGD_SHA512,
            pucPublicKey,
            uiPublicKeyLen,
            ucInData,
            sizeof(ucInData),
            ucSignature,
            uiSignatureLen);
    EXPECT_EQ(rv, 0);
    rv = CY_EccVerifySign(
            SGD_SHA512,
            pucPublicKey,
            uiPublicKeyLen,
            ucInData,
            sizeof(ucInData),
            ucSignature1,
            sizeof(ucSignature1));
    EXPECT_EQ(rv, CY_R_VERIFY_ERR);
    std::ofstream file("./testfile");
    file << "Hello, world!" << std::endl;
    uiSignatureLen = 1024;
    rv = CY_EccSignFile(
            hAppHandle,
            (unsigned char *) pcContainerName,
            strlen(pcContainerName),
            (unsigned char *) pcPin,
            strlen(pcPin),
            SGD_SHA512,
            "./testfile",
            ucSignature,
            &uiSignatureLen);
    EXPECT_EQ(rv, 0);
    rv = CY_EccVerifySignFile(
            SGD_SHA512,
            pucPublicKey,
            uiPublicKeyLen,
            "./testfile",
            ucSignature,
            uiSignatureLen);
    EXPECT_EQ(rv, 0);
    rv = CY_EccVerifySignFile(
            SGD_SHA512,
            pucPublicKey,
            uiPublicKeyLen,
            "./testfile",
            ucSignature1,
            sizeof(ucSignature1));
    EXPECT_EQ(rv, CY_R_VERIFY_ERR);
    rv = CY_Finalize(hAppHandle);
    EXPECT_EQ(rv, 0);
    hAppHandle = nullptr;
}