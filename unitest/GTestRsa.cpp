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

TEST(RsaTest, Rsa2048) {
    void *hAppHandle = nullptr;
    const char *pcContainerName = "rsa_2048";
    const char *pcPin = "rsa_2048";
    unsigned int uiKeyBits = 2048;
    int rv = CY_InitService(&hAppHandle, "./cyber");
    EXPECT_EQ(rv, CY_R_SUCCESS);
    rv = CY_GenRsaKeyPair(
            hAppHandle,
            (unsigned char *)pcContainerName,
            strlen(pcContainerName),
            (unsigned char *) pcPin,
            strlen(pcPin),
            uiKeyBits,
            SGD_KEYUSAGE_SIGN,
            0);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    unsigned char pucPublicKey[1024] = {0};
    unsigned int uiPublicKeyLen = 1024;
    rv = CY_GetRsaPublicKey(
            hAppHandle,
            (unsigned char *)pcContainerName,
            strlen(pcContainerName),
            SGD_KEYUSAGE_SIGN,
            pucPublicKey,
            &uiPublicKeyLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    unsigned char ucInData[] = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    unsigned char ucSignature[1024] = {0};
    unsigned int uiSignatureLen = 1024;
    unsigned char ucSignature1[] = {
            0xbe, 0xf3, 0x33, 0x0c, 0x8a, 0xa3, 0x42, 0xaf, 0xc8, 0xc2, 0x4f, 0x50, 0xbb, 0x73, 0x50, 0xf0,
            0xa3, 0xc5, 0x31, 0xa0, 0xab, 0x3b, 0xdd, 0x66, 0xb2, 0x97, 0xdb, 0x61, 0x25, 0xd1, 0x7f, 0xc1,
            0xbe, 0x0c, 0xe2, 0x9b, 0x4c, 0x10, 0x43, 0xe9, 0x1d, 0x68, 0xf7, 0xab, 0xc6, 0x37, 0x2c, 0x6e,
            0x2a, 0x24, 0x0a, 0x0f, 0x3e, 0x50, 0x2d, 0xec, 0xb8, 0x4b, 0x81, 0x9c, 0xca, 0x4b, 0xea, 0xbe,
            0xf9, 0x38, 0x61, 0x34, 0x31, 0xa9, 0x33, 0xea, 0x12, 0x76, 0x19, 0x2c, 0x13, 0xe3, 0xe9, 0x93,
            0x43, 0x78, 0x79, 0x64, 0x1a, 0x00, 0x96, 0x0a, 0x86, 0xab, 0x0c, 0x8e, 0x8a, 0x07, 0xcc, 0x94,
            0x5a, 0x5e, 0xc0, 0xa2, 0x72, 0x36, 0x8d, 0x59, 0xd9, 0xe0, 0x1e, 0x88, 0x1b, 0x75, 0xb1, 0x63,
            0x19, 0x43, 0x7d, 0xac, 0xb6, 0x23, 0xd5, 0x32, 0x47, 0x63, 0x51, 0x41, 0x43, 0x8a, 0x21, 0x05,
            0xc2, 0x7a, 0x76, 0x03, 0xb5, 0xc1, 0x9f, 0x80, 0xf7, 0x4b, 0xd1, 0x83, 0x0f, 0xec, 0x80, 0x72,
            0x56, 0x5f, 0x55, 0xb3, 0xbb, 0xaa, 0x09, 0xc3, 0x9f, 0x5d, 0xd2, 0xe0, 0x04, 0xd7, 0xcf, 0x2b,
            0x38, 0x15, 0x54, 0xa8, 0xa2, 0x15, 0xbd, 0xa7, 0x0d, 0xbb, 0xf3, 0x67, 0xf0, 0xe0, 0x3a, 0xb9,
            0xff, 0xc5, 0x95, 0x74, 0x96, 0x81, 0x3e, 0x06, 0x6c, 0x09, 0xa5, 0xec, 0x20, 0xec, 0x7a, 0xd5,
            0xe3, 0x7f, 0xaf, 0x5e, 0xf2, 0xf8, 0x62, 0x72, 0xfc, 0x72, 0x32, 0x1c, 0xd6, 0xff, 0xdc, 0x4b,
            0x53, 0x95, 0xbf, 0xf5, 0xd8, 0x85, 0xf3, 0xf6, 0x6d, 0x1d, 0x41, 0xc7, 0xc0, 0x84, 0x3f, 0xc6,
            0xe8, 0x85, 0x98, 0x90, 0x6f, 0xb2, 0x01, 0x6d, 0x63, 0x1e, 0x8b, 0x30, 0xbc, 0x41, 0x96, 0x52,
            0x96, 0x54, 0x2f, 0xea, 0xe5, 0xa2, 0x30, 0x69, 0xf2, 0xe6, 0xb3, 0x14, 0xb6, 0x85, 0x90, 0x22
    };
    rv = CY_RsaSign(
            hAppHandle,
            (unsigned char *)pcContainerName,
            strlen(pcContainerName),
            (unsigned char *) pcPin,
            strlen(pcPin),
            SGD_SHA512,
            ucInData,
            sizeof(ucInData),
            ucSignature,
            &uiSignatureLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    EXPECT_EQ(uiSignatureLen, uiKeyBits / 8);
    rv = CY_RsaVerifySign(
            SGD_SHA512,
            pucPublicKey,
            uiPublicKeyLen,
            ucInData,
            sizeof(ucInData),
            ucSignature,
            uiSignatureLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    rv = CY_RsaVerifySign(
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
    rv = CY_RsaSignFile(
            hAppHandle,
            (unsigned char *)pcContainerName,
            strlen(pcContainerName),
            (unsigned char *) pcPin,
            strlen(pcPin),
            SGD_SHA512,
            "./testfile",
            ucSignature,
            &uiSignatureLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    rv = CY_RsaVerifySignFile(
            SGD_SHA512,
            pucPublicKey,
            uiPublicKeyLen,
            "./testfile",
            ucSignature,
            uiSignatureLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    rv = CY_RsaVerifySignFile(
            SGD_SHA512,
            pucPublicKey,
            uiPublicKeyLen,
            "./testfile",
            ucSignature1,
            sizeof(ucSignature1));
    EXPECT_EQ(rv, CY_R_VERIFY_ERR);

    unsigned char ucCipherData[1024] = {0};
    unsigned int uiCipherDataLen = 1024;
    rv = CY_RsaEncrypt(
            pucPublicKey,
            uiPublicKeyLen,
            ucInData,
            sizeof(ucInData),
            ucCipherData,
            &uiCipherDataLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    EXPECT_EQ(uiCipherDataLen, uiKeyBits / 8);
    unsigned char ucPlainData[1024] = {0};
    unsigned int uiPlainDataLen = 1024;
    rv = CY_RsaDecrypt(
            hAppHandle,
            (unsigned char *)pcContainerName,
            strlen(pcContainerName),
            (unsigned char *) pcPin,
            strlen(pcPin),
            ucCipherData,
            uiCipherDataLen,
            ucPlainData,
            &uiPlainDataLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    EXPECT_EQ(memcmp(ucPlainData, ucInData, uiPlainDataLen), 0);
    rv = CY_Finalize(hAppHandle);
    EXPECT_EQ(rv, 0);
    hAppHandle = nullptr;
}

TEST(RsaTest, Rsa3072) {
    void *hAppHandle = nullptr;
    const char *pcContainerName = "rsa_3072";
    const char *pcPin = "rsa_3072";
    unsigned int uiKeyBits = 3072;
    int rv = CY_InitService(&hAppHandle,
                            "./cyber");
    EXPECT_EQ(rv, CY_R_SUCCESS);
    rv = CY_GenRsaKeyPair(
            hAppHandle,
            (unsigned char *)pcContainerName,
            strlen(pcContainerName),
            (unsigned char *) pcPin,
            strlen(pcPin),
            uiKeyBits,
            SGD_KEYUSAGE_SIGN,
            0);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    unsigned char pucPublicKey[1024] = {0};
    unsigned int uiPublicKeyLen = 1024;
    rv = CY_GetRsaPublicKey(
            hAppHandle,
            (unsigned char *)pcContainerName,
            strlen(pcContainerName),
            SGD_KEYUSAGE_SIGN,
            pucPublicKey,
            &uiPublicKeyLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    unsigned char ucInData[] = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    unsigned char ucSignature[1024] = {0};
    unsigned int uiSignatureLen = 1024;
    unsigned char ucSignature1[] = {
            0x5f, 0x38, 0xa7, 0x17, 0x61, 0xe2, 0xfa, 0x9e, 0xa8, 0x01, 0x1e, 0x32, 0x17, 0x5b, 0xd6, 0xc9,
            0xc9, 0x15, 0xe6, 0xcf, 0x81, 0xa7, 0x3a, 0x84, 0x40, 0xad, 0x48, 0xe5, 0xbf, 0xdb, 0xde, 0xdf,
            0xc8, 0x73, 0x56, 0x84, 0xdd, 0xae, 0xf6, 0xcf, 0x81, 0x3b, 0xa5, 0x20, 0xdd, 0xe2, 0xfb, 0xec,
            0x6c, 0xff, 0x0b, 0x8b, 0x38, 0xd6, 0x00, 0xe0, 0x0b, 0xe6, 0x27, 0xfb, 0x2c, 0x7a, 0x77, 0x77,
            0x2e, 0xaf, 0x1d, 0x65, 0x80, 0x0d, 0xa3, 0xb2, 0x24, 0x69, 0xb5, 0x74, 0xf8, 0xee, 0x63, 0x44,
            0x5c, 0x9d, 0x1a, 0xe0, 0x65, 0xcd, 0x78, 0x52, 0x10, 0xcc, 0x29, 0xd9, 0x1f, 0x86, 0x82, 0x28,
            0x36, 0x35, 0x77, 0x5e, 0xce, 0xe0, 0xb2, 0xd8, 0x08, 0x2e, 0x36, 0xad, 0xa0, 0x02, 0x97, 0x6b,
            0x07, 0x6e, 0xc9, 0xdf, 0x80, 0x5c, 0xf3, 0x2f, 0x52, 0x6d, 0x37, 0x11, 0x2c, 0x6f, 0x32, 0x8b,
            0x9b, 0xeb, 0x11, 0xcc, 0xeb, 0x3a, 0x6a, 0x9b, 0xe8, 0x9b, 0xa2, 0x31, 0x14, 0x63, 0x52, 0x05,
            0x61, 0x65, 0xb3, 0x81, 0x65, 0x2a, 0x2f, 0x31, 0x81, 0xf2, 0xdb, 0xe6, 0x5e, 0xd6, 0x32, 0x3c,
            0x4e, 0x19, 0xf0, 0x9f, 0x4a, 0x67, 0x4f, 0xe8, 0x78, 0x40, 0xd2, 0xb6, 0x49, 0xcc, 0x16, 0xae,
            0x3d, 0x0e, 0x54, 0xe1, 0xe3, 0x6f, 0xb6, 0x05, 0xdf, 0xe0, 0xc0, 0xb8, 0xb9, 0xbb, 0x9e, 0x5b,
            0x50, 0x48, 0x11, 0x7b, 0xa6, 0x39, 0x2b, 0x64, 0x76, 0x97, 0x84, 0x55, 0xd3, 0xcc, 0x00, 0x5e,
            0xbb, 0x5e, 0xda, 0x7d, 0x76, 0x19, 0xd5, 0x3f, 0xa0, 0x91, 0xb9, 0xc4, 0x8a, 0xf0, 0xb9, 0x5d,
            0xf9, 0x6d, 0x95, 0x19, 0x9a, 0x06, 0x45, 0x97, 0xaf, 0x2c, 0x90, 0x8e, 0xea, 0xac, 0xcd, 0x2e,
            0x5e, 0xe8, 0x38, 0xe6, 0x92, 0x53, 0x2a, 0x7c, 0x58, 0x2c, 0xeb, 0x2f, 0xad, 0xca, 0x87, 0x70,
            0xd8, 0xcf, 0x63, 0x55, 0x01, 0x39, 0xb2, 0x63, 0x0e, 0xb1, 0xa9, 0x20, 0xef, 0xe6, 0x47, 0xb0,
            0x10, 0x64, 0x75, 0x29, 0xac, 0xaa, 0x5f, 0x0e, 0x68, 0x48, 0x7b, 0x39, 0x98, 0x39, 0xd6, 0x8d,
            0xc9, 0xe8, 0x83, 0x31, 0x64, 0x90, 0xb4, 0xc8, 0xe7, 0xfb, 0x5e, 0x13, 0x01, 0x99, 0x0c, 0x71,
            0xc2, 0x7f, 0xdb, 0x25, 0x73, 0x9c, 0x31, 0x06, 0xf0, 0x3e, 0x8d, 0xf9, 0x21, 0x90, 0xe8, 0xfb,
            0x99, 0xd2, 0xe0, 0xff, 0x0c, 0x0a, 0x42, 0xb4, 0x92, 0x89, 0xe9, 0x63, 0x96, 0x4b, 0x23, 0x9e,
            0xc8, 0x58, 0x08, 0x3a, 0x8b, 0xc8, 0xf3, 0xeb, 0x8c, 0xa4, 0x47, 0xfa, 0x3c, 0x84, 0x38, 0xa0,
            0x7c, 0x24, 0xeb, 0x5b, 0x4c, 0x3d, 0x10, 0x67, 0xd7, 0xea, 0xb6, 0x5c, 0x07, 0x64, 0x21, 0xb7,
            0xf5, 0x2e, 0x3d, 0x5c, 0xc6, 0xb8, 0xbd, 0x72, 0x4a, 0xa9, 0x4b, 0x6a, 0xf0, 0xe0, 0x9d, 0x28
    };
    rv = CY_RsaSign(
            hAppHandle,
            (unsigned char *)pcContainerName,
            strlen(pcContainerName),
            (unsigned char *) pcPin,
            strlen(pcPin),
            SGD_SHA512,
            ucInData,
            sizeof(ucInData),
            ucSignature,
            &uiSignatureLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    EXPECT_EQ(uiSignatureLen, uiKeyBits / 8);
    rv = CY_RsaVerifySign(
            SGD_SHA512,
            pucPublicKey,
            uiPublicKeyLen,
            ucInData,
            sizeof(ucInData),
            ucSignature,
            uiSignatureLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    rv = CY_RsaVerifySign(
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
    rv = CY_RsaSignFile(
            hAppHandle,
            (unsigned char *)pcContainerName,
            strlen(pcContainerName),
            (unsigned char *) pcPin,
            strlen(pcPin),
            SGD_SHA512,
            "./testfile",
            ucSignature,
            &uiSignatureLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    rv = CY_RsaVerifySignFile(
            SGD_SHA512,
            pucPublicKey,
            uiPublicKeyLen,
            "./testfile",
            ucSignature,
            uiSignatureLen);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    rv = CY_RsaVerifySignFile(
            SGD_SHA512,
            pucPublicKey,
            uiPublicKeyLen,
            "./testfile",
            ucSignature1,
            sizeof(ucSignature1));
    EXPECT_EQ(rv, CY_R_VERIFY_ERR);
    rv = CY_Finalize(hAppHandle);
    EXPECT_EQ(rv, CY_R_SUCCESS);
    hAppHandle = nullptr;
}

// He's too slow, marked it disable, on if necessary.
//TEST(DISABLED_RsaTest, Rsa4096) {
//    void *hAppHandle = nullptr;
//    const char *pcContainerName = "rsa_4096";
//    const char *pcPin = "rsa_4096";
//    unsigned int uiKeyBits = 4096;
//    int rv = CY_InitService(&hAppHandle,
//                            "./cyber",
//                            nullptr,
//                            nullptr,
//                            0);
//    EXPECT_EQ(rv, CY_R_SUCCESS);
//    rv = CY_GenRsaKeyPair(
//            hAppHandle,
//            (unsigned char *)pcContainerName,
//            strlen(pcContainerName),
//            (unsigned char *) pcPin,
//            strlen(pcPin),
//            uiKeyBits,
//            SGD_KEYUSAGE_SIGN,
//            0);
//    EXPECT_EQ(rv, CY_R_SUCCESS);
//    unsigned char pucPublicKey[2048] = {0};
//    unsigned int uiPublicKeyLen = 2048;
//    rv = CY_GetRsaPublicKey(
//            hAppHandle,
//            (unsigned char *)pcContainerName,
//            strlen(pcContainerName),
//            SGD_KEYUSAGE_SIGN,
//            pucPublicKey,
//            &uiPublicKeyLen);
//    EXPECT_EQ(rv, CY_R_SUCCESS);
//    unsigned char ucInData[] = {
//            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
//    unsigned char ucSignature[2048] = {0};
//    unsigned int uiSignatureLen = 2048;
//    unsigned char ucSignature1[] = {
//            0x47, 0x61, 0x9b, 0x5a, 0xac, 0xbd, 0x9e, 0x61, 0xe1, 0xdf, 0x5d, 0xbb, 0x37, 0xc7, 0xef, 0x46,
//            0xfd, 0x7c, 0x80, 0xd0, 0xd8, 0x20, 0x7e, 0xf5, 0xb3, 0x3c, 0x7a, 0x4d, 0x36, 0xa5, 0xad, 0x5c,
//            0xb1, 0x1c, 0x13, 0x03, 0xd0, 0x0c, 0x5c, 0x8d, 0x64, 0xc6, 0xdb, 0x9a, 0xeb, 0xe7, 0x3e, 0x4d,
//            0x5f, 0x71, 0x7c, 0x61, 0x01, 0x98, 0x27, 0x39, 0xb1, 0xc6, 0xe2, 0x0b, 0x6c, 0x61, 0x9a, 0xc8,
//            0xb8, 0x57, 0xea, 0x6a, 0x3a, 0xd5, 0x95, 0x2e, 0x43, 0x3e, 0xcc, 0x70, 0x12, 0x7f, 0x01, 0xa4,
//            0xfe, 0x5f, 0x1e, 0xbe, 0x1a, 0xb9, 0xb2, 0xfa, 0x8a, 0x01, 0x49, 0x4a, 0x37, 0x02, 0x54, 0x12,
//            0x7d, 0x16, 0x50, 0xd6, 0x3f, 0x73, 0xcf, 0xfc, 0x4e, 0x9d, 0x3e, 0xd1, 0x0e, 0x16, 0x3e, 0x77,
//            0x58, 0x5a, 0xfc, 0x1f, 0x3c, 0x34, 0x22, 0x72, 0xf9, 0xe4, 0x5b, 0xad, 0x35, 0xa3, 0x0c, 0x52,
//            0x26, 0x9d, 0x41, 0xe5, 0x91, 0x64, 0xcb, 0x9d, 0xb4, 0x6e, 0x11, 0xc7, 0x32, 0xb0, 0xfc, 0xd3,
//            0x3f, 0xf0, 0x5c, 0xf4, 0x31, 0x97, 0xfd, 0x7e, 0x50, 0xda, 0x4a, 0x76, 0x91, 0x96, 0xcf, 0x42,
//            0x3a, 0xe7, 0x5c, 0x7e, 0x33, 0xd4, 0x5e, 0xe1, 0x49, 0x75, 0x02, 0x7f, 0x19, 0xf9, 0x53, 0x8a,
//            0xd5, 0x95, 0xe2, 0x92, 0x15, 0x7f, 0x73, 0x2b, 0x52, 0xfb, 0x96, 0x92, 0xc6, 0x0e, 0xe6, 0xab,
//            0xf7, 0xa7, 0x67, 0x87, 0xf3, 0xfb, 0x17, 0x02, 0x14, 0xf1, 0x93, 0xd7, 0x98, 0x09, 0x07, 0x65,
//            0xe2, 0xbf, 0x40, 0x06, 0x07, 0xa0, 0x43, 0xe2, 0xf3, 0x06, 0x55, 0x19, 0xf4, 0xc1, 0xf0, 0x4a,
//            0xd5, 0xa6, 0x3b, 0x20, 0x0e, 0xad, 0xfe, 0x66, 0x37, 0xff, 0xc8, 0x42, 0xf5, 0xe4, 0x0a, 0x78,
//            0x8d, 0xcf, 0xad, 0x32, 0x97, 0xd2, 0xaa, 0x20, 0x9f, 0x8f, 0xd6, 0x8b, 0xf1, 0x71, 0x39, 0xec,
//            0xbf, 0x2d, 0xa2, 0xd2, 0x5d, 0x2e, 0x0b, 0x3b, 0x18, 0x4b, 0x18, 0xf1, 0xca, 0xd8, 0x80, 0xc7,
//            0x1a, 0xfd, 0xa7, 0x14, 0xb8, 0x5b, 0xf1, 0x3d, 0xdc, 0x22, 0xa7, 0x03, 0xee, 0x27, 0xca, 0xbd,
//            0xb8, 0x28, 0xaa, 0xa3, 0x7c, 0x9f, 0xeb, 0xaf, 0xb2, 0x7b, 0x04, 0xb8, 0x4b, 0x46, 0x42, 0xe0,
//            0x61, 0x86, 0x8e, 0x87, 0x14, 0x9e, 0xe8, 0xdf, 0x5c, 0x28, 0x08, 0xe1, 0x14, 0xe7, 0x61, 0xea,
//            0x22, 0xc2, 0xa6, 0x35, 0x9e, 0x80, 0xa8, 0x65, 0x7c, 0xac, 0xcf, 0xe8, 0x9a, 0xb9, 0x4e, 0x7a,
//            0x14, 0xcb, 0xb3, 0x1b, 0xdb, 0xc1, 0x59, 0x21, 0xd4, 0xb6, 0x5c, 0x5a, 0x89, 0x7a, 0x74, 0xd3,
//            0x58, 0x90, 0x79, 0x21, 0xd2, 0x33, 0x4f, 0x1c, 0xc6, 0x1f, 0x96, 0xe3, 0x3e, 0x8b, 0xad, 0x89,
//            0xbe, 0xc2, 0x18, 0x04, 0x9c, 0x63, 0x70, 0x13, 0xa4, 0xe4, 0x68, 0x97, 0x15, 0x9b, 0x14, 0x0f,
//            0x49, 0x1b, 0x64, 0xd5, 0x9b, 0x91, 0x2f, 0x81, 0x47, 0xb7, 0x1a, 0xba, 0xf8, 0x65, 0x9f, 0x1e,
//            0x35, 0x82, 0x4a, 0x85, 0x8a, 0x29, 0xac, 0xae, 0xb7, 0xf1, 0xc2, 0x67, 0x30, 0x3e, 0x53, 0x79,
//            0x80, 0xe8, 0xe8, 0x08, 0x77, 0x12, 0x60, 0x04, 0x7c, 0x66, 0x36, 0x9d, 0xcb, 0xc7, 0x07, 0x41,
//            0x0f, 0x0c, 0xdd, 0x0b, 0xb0, 0x8b, 0xca, 0xbc, 0x45, 0xce, 0xd1, 0x17, 0xef, 0x0c, 0x14, 0xb4,
//            0xd2, 0x90, 0xf7, 0x4e, 0x6b, 0xd1, 0x39, 0x1f, 0x5c, 0x0e, 0x5c, 0x8a, 0xf5, 0x52, 0xff, 0x32,
//            0x87, 0xab, 0xe2, 0xc4, 0x4d, 0x4c, 0x50, 0x67, 0xa7, 0x7f, 0xed, 0x28, 0xac, 0x84, 0x98, 0x7b,
//            0x66, 0xda, 0xb0, 0x6d, 0x9e, 0xb6, 0x3c, 0x77, 0xb0, 0x72, 0x7c, 0xf4, 0x91, 0xee, 0x45, 0xc7,
//            0xef, 0x55, 0xbd, 0x8b, 0x9c, 0xc2, 0x68, 0xcf, 0x06, 0x73, 0xe2, 0x9d, 0x35, 0x4e, 0x7d, 0xb9
//    };
//    // RSA PKCS1 Make Signature And Verify Signature.
//    rv = CY_RsaSign(
//            hAppHandle,
//            (unsigned char *)pcContainerName,
//            strlen(pcContainerName),
//            (unsigned char *) pcPin,
//            strlen(pcPin),
//            SGD_SHA512,
//            ucInData,
//            sizeof(ucInData),
//            ucSignature,
//            &uiSignatureLen);
//    EXPECT_EQ(rv, CY_R_SUCCESS);
//    EXPECT_EQ(uiSignatureLen, uiKeyBits / 8);
//
//    rv = CY_RsaVerifySign(
//            SGD_SHA512,
//            pucPublicKey,
//            uiPublicKeyLen,
//            ucInData,
//            sizeof(ucInData),
//            ucSignature,
//            uiSignatureLen);
//    EXPECT_EQ(rv, CY_R_SUCCESS);
//
//    rv = CY_RsaVerifySign(
//            SGD_SHA512,
//            pucPublicKey,
//            uiPublicKeyLen,
//            ucInData,
//            sizeof(ucInData),
//            ucSignature1,
//            sizeof(ucSignature1));
//    EXPECT_EQ(rv, CY_R_VERIFY_ERR);
//
//    // RSA PSS Make Signature And Verify Signature.
//    uiSignatureLen = 2048;
//    rv = CY_RsaSignPss(
//            hAppHandle,
//            (unsigned char *)pcContainerName,
//            strlen(pcContainerName),
//            (unsigned char *) pcPin,
//            strlen(pcPin),
//            SGD_SHA512,
//            ucInData,
//            sizeof(ucInData),
//            ucSignature,
//            &uiSignatureLen);
//    EXPECT_EQ(rv, CY_R_SUCCESS);
//
//    rv = CY_RsaVerifySignPss(
//            SGD_SHA512,
//            pucPublicKey,
//            uiPublicKeyLen,
//            ucInData,
//            sizeof(ucInData),
//            ucSignature,
//            uiSignatureLen);
//    EXPECT_EQ(rv, CY_R_SUCCESS);
//
//    std::ofstream file("./testfile");
//    file << "Hello, world!" << std::endl;
//    uiSignatureLen = 1024;
//    rv = CY_RsaSignFile(
//            hAppHandle,
//            (unsigned char *)pcContainerName,
//            strlen(pcContainerName),
//            (unsigned char *) pcPin,
//            strlen(pcPin),
//            SGD_SHA512,
//            "./testfile",
//            ucSignature,
//            &uiSignatureLen);
//    EXPECT_EQ(rv, CY_R_SUCCESS);
//    rv = CY_RsaVerifySignFile(
//            SGD_SHA512,
//            pucPublicKey,
//            uiPublicKeyLen,
//            "./testfile",
//            ucSignature,
//            uiSignatureLen);
//    EXPECT_EQ(rv, CY_R_SUCCESS);
//    rv = CY_RsaVerifySignFile(
//            SGD_SHA512,
//            pucPublicKey,
//            uiPublicKeyLen,
//            "./testfile",
//            ucSignature1,
//            sizeof(ucSignature1));
//    EXPECT_EQ(rv, CY_R_VERIFY_ERR);
//    rv = CY_Finalize(hAppHandle);
//    EXPECT_EQ(rv, CY_R_SUCCESS);
//    hAppHandle = nullptr;
//}