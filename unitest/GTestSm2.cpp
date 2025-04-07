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

TEST(EccTest, SM2) {
    void *hAppHandle = nullptr;
    const char *pcContainerName = "sm2";
    const char *pcPin = "sm2";
    int rv = CY_InitService(&hAppHandle,
                            "./cyber");
    EXPECT_EQ(rv, CY_R_SUCCESS);
    rv = CY_GenEccKeyPair(
            hAppHandle,
            (unsigned char *) pcContainerName,
            strlen(pcContainerName),
            (unsigned char *) pcPin,
            strlen(pcPin),
            SGD_SM2,
            SGD_KEYUSAGE_SIGN,
            1);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    unsigned char pucPublicKey[1024] = {0};
    unsigned int uiPublicKeyLen = 1024;
    rv = CY_GetEccPublicKey(
            hAppHandle,
            (unsigned char *) pcContainerName,
            strlen(pcContainerName),
            SGD_KEYUSAGE_SIGN,
            pucPublicKey,
            &uiPublicKeyLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);
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
            SGD_SM3,
            ucInData,
            sizeof(ucInData),
            ucSignature,
            &uiSignatureLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    rv = CY_EccVerifySign(
            SGD_SM3,
            pucPublicKey,
            uiPublicKeyLen,
            ucInData,
            sizeof(ucInData),
            ucSignature,
            uiSignatureLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    rv = CY_EccVerifySign(
            SGD_SM3,
            pucPublicKey,
            uiPublicKeyLen,
            ucInData,
            sizeof(ucInData),
            ucSignature1,
            sizeof(ucSignature1));
    EXPECT_EQ(rv, CY_R_VERIFY_ERR);

    // Standard SM2 verification
    unsigned char ucPublicKey2[] = {
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
            0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55,
            0x01, 0x82, 0x2d, 0x03, 0x42, 0x00, 0x04, 0x64, 0xfe, 0x0d,
            0xe3, 0xea, 0x39, 0x44, 0x0d, 0xf4, 0xc1, 0xfc, 0xb8, 0xc2,
            0xa2, 0x95, 0x9c, 0xe5, 0x82, 0x8d, 0x18, 0x25, 0x27, 0x01,
            0xe6, 0x6e, 0x53, 0x34, 0xb8, 0xa1, 0xf8, 0x7e, 0xc3, 0x7c,
            0x04, 0xaa, 0x30, 0x4e, 0xbb, 0x5b, 0xc3, 0x15, 0x86, 0x56,
            0x0e, 0x04, 0x11, 0x47, 0xdf, 0x03, 0x21, 0xd5, 0x37, 0xf7,
            0x7e, 0x71, 0x7c, 0xce, 0xc2, 0x6b, 0xfd, 0xc9, 0x4d, 0xe9,
            0x17
    };
    unsigned char ucSignature2[] = {
            0x30, 0x46, 0x02, 0x21, 0x00, 0xd4, 0x2f, 0xf1, 0x0e, 0xc2,
            0xc5, 0xde, 0x9f, 0x8b, 0x71, 0x27, 0x3e, 0x6c, 0xbe, 0x22,
            0xfb, 0x46, 0xd1, 0xc8, 0xb3, 0x77, 0x89, 0xe4, 0x82, 0xb7,
            0x1b, 0x2d, 0xcc, 0xb0, 0x14, 0x6c, 0x04, 0x02, 0x21, 0x00,
            0x97, 0x8c, 0x31, 0x33, 0x38, 0xb9, 0xbd, 0x98, 0xa8, 0xad,
            0x32, 0x08, 0x24, 0x8a, 0x44, 0x38, 0x1d, 0x09, 0x38, 0xfe,
            0xda, 0xdd, 0x6b, 0x2e, 0xe2, 0x16, 0x9f, 0xba, 0xc1, 0x4d,
            0x57, 0xa2
    };
    rv = CY_EccVerifySign(
            SGD_SM3,
            ucPublicKey2,
            sizeof(ucPublicKey2),
            ucInData,
            sizeof(ucInData),
            ucSignature2,
            sizeof(ucSignature2));
    EXPECT_EQ(rv, CY_R_SUCCESS);

    std::ofstream file("./testfile");
    file << "Hello, world!" << std::endl;
    uiSignatureLen = 1024;
    rv = CY_EccSignFile(
            hAppHandle,
            (unsigned char *) pcContainerName,
            strlen(pcContainerName),
            (unsigned char *) pcPin,
            strlen(pcPin),
            SGD_SM3,
            "./testfile",
            ucSignature,
            &uiSignatureLen);
    EXPECT_EQ(rv, 0);
    rv = CY_EccVerifySignFile(
            SGD_SM3,
            pucPublicKey,
            uiPublicKeyLen,
            "./testfile",
            ucSignature,
            uiSignatureLen);
    EXPECT_EQ(rv, 0);
    rv = CY_EccVerifySignFile(
            SGD_SM3,
            pucPublicKey,
            uiPublicKeyLen,
            "./testfile",
            ucSignature1,
            sizeof(ucSignature1));
    EXPECT_EQ(rv, CY_R_VERIFY_ERR);

    unsigned char pucCipher[256] = {0};
    unsigned int uiCipherLen = 256;
    rv = CY_EccEncrypt(
            pucPublicKey,
            uiPublicKeyLen,
            ucInData,
            sizeof(ucInData),
            pucCipher,
            &uiCipherLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);

    unsigned char pucPlain[256] = {0};
    unsigned int uiPlainLen = 256;
    rv = CY_EccDecrypt(
            hAppHandle,
            (unsigned char *) pcContainerName,
            strlen(pcContainerName),
            (unsigned char *) pcPin,
            strlen(pcPin),
            pucCipher,
            uiCipherLen,
            pucPlain,
            &uiPlainLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    EXPECT_EQ(uiPlainLen, sizeof(ucInData));
    EXPECT_EQ(memcmp(ucInData, pucPlain, uiPlainLen), 0);

    rv = CY_Finalize(hAppHandle);
    EXPECT_EQ(rv, 0);
    hAppHandle = nullptr;
}