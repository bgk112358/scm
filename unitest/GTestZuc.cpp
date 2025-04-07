// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#include "gtest/gtest.h"
#include <cstring>
extern "C" {
#include "cyber_pki.h"
}

// test data from /Tongsuo-8.3.3/test/recipes/30-test_evp_data/evpciph.txt

TEST(ZucTest, ZucTest) {
    // ENCRYPT
    void *hSymmKeyObj = nullptr;
    unsigned char ucKey[] = {
            0x17, 0x3d, 0x14, 0xba, 0x50, 0x03, 0x73, 0x1d, 0x7a, 0x60, 0x04, 0x94, 0x70, 0xf0, 0x0a, 0x29 };
    unsigned int uiKeyLen = sizeof(ucKey);

    unsigned char ucIv[] = {
            0x66, 0x03, 0x54, 0x92, 0x78 };
    unsigned int uiIvLen = sizeof(ucKey);

    int rv = CY_CreateSymmKeyObj(
            &hSymmKeyObj,
            ucKey,
            uiKeyLen,
            ucIv,
            uiIvLen,
            SGD_ENC,
            SGD_ZUC);
    ASSERT_EQ(rv, 0);
    unsigned char pucInData[] = {
            0x6c, 0xf6, 0x53, 0x40, 0x73, 0x55, 0x52, 0xab, 0x0c, 0x97,
            0x52, 0xfa, 0x6f, 0x90, 0x25, 0xfe, 0x0b, 0xd6, 0x75, 0xd9,
            0x00, 0x58, 0x75, 0xb2 };

    unsigned int uiInDataLen = sizeof(pucInData);
    unsigned char ucOutData[128] = {0};
    unsigned int uiOutDataLen = 128;

    unsigned char ucExpected[] = {
            0xa6, 0xc8, 0x5f, 0xc6, 0x6a, 0xfb, 0x85, 0x33, 0xaa, 0xfc,
            0x25, 0x18, 0xdf, 0xe7, 0x84, 0x94, 0x0e, 0xe1, 0xe4, 0xb0,
            0x30, 0x23, 0x8c, 0xc8 };

    rv = CY_SymmEncryptUpdate(
            hSymmKeyObj,
            pucInData, uiInDataLen,
            ucOutData, &uiOutDataLen);
    ASSERT_EQ(rv, 0);

    unsigned int final_len = 16;
    rv = CY_SymmEncryptFinal(
            hSymmKeyObj,
            ucOutData + uiOutDataLen,
            &final_len);
    ASSERT_EQ(rv, 0);
    final_len += uiOutDataLen;
    EXPECT_TRUE(std::memcmp(ucOutData, ucExpected, final_len) == 0);
    CY_DestroySymmKeyObj(hSymmKeyObj);
}