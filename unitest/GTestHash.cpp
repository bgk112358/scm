// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//
#include "gtest/gtest.h"
#include <cstring>
extern "C" {
#include "cyber_pki.h"
}

TEST(HashTest, SHA1Test) {
    unsigned char pucInData[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    unsigned int uiInDataLen  = sizeof(pucInData);
    unsigned char pucOutData[20] = {0};
    unsigned int  puiOutDataLen  = 20;
    unsigned char ucExpected[20] = {
            0x7c, 0x22, 0x2f, 0xb2, 0x92, 0x7d, 0x82, 0x8a,
            0xf2, 0x2f, 0x59, 0x21, 0x34, 0xe8, 0x93, 0x24,
            0x80, 0x63, 0x7c, 0x0d };
    unsigned int  ucExpectedLen = 20;
    int rv = CY_Hash(SGD_SHA1, pucInData, uiInDataLen, pucOutData, &puiOutDataLen);
    ASSERT_EQ(rv, 0);
    ASSERT_EQ(puiOutDataLen, ucExpectedLen);
    EXPECT_TRUE(std::memcmp(pucOutData, ucExpected, puiOutDataLen) == 0);
}

TEST(HashTest, SHA1UpdateTest) {
    unsigned char pucInData[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    unsigned int uiInDataLen  = sizeof(pucInData);
    unsigned char pucOutData[20] = {0};
    unsigned int  puiOutDataLen  = 20;
    unsigned char ucExpected[20] = {
            0x7c, 0x22, 0x2f, 0xb2, 0x92, 0x7d, 0x82, 0x8a,
            0xf2, 0x2f, 0x59, 0x21, 0x34, 0xe8, 0x93, 0x24,
            0x80, 0x63, 0x7c, 0x0d };
    unsigned int  ucExpectedLen = 20;
    void *phHashObj = nullptr;
    int rv = CY_CreateHashObj(&phHashObj, SGD_SHA1);
    ASSERT_EQ(rv, 0);
    rv = CY_HashUpdate(phHashObj, pucInData, uiInDataLen);
    ASSERT_EQ(rv, 0);
    rv = CY_HashFinal(phHashObj, pucOutData, &puiOutDataLen);
    ASSERT_EQ(rv, 0);
    CY_DestroyHashObj(phHashObj);
    ASSERT_EQ(puiOutDataLen, ucExpectedLen);
    EXPECT_TRUE(std::memcmp(pucOutData, ucExpected, puiOutDataLen) == 0);
}

TEST(HashTest, SHA256Test) {
    unsigned char pucInData[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    unsigned int uiInDataLen  = sizeof(pucInData);
    unsigned char pucOutData[32] = {0};
    unsigned int  puiOutDataLen  = 32;
    unsigned char ucExpected[32] = {
            0xef, 0x79, 0x7c, 0x81, 0x18, 0xf0, 0x2d, 0xfb,
            0x64, 0x96, 0x07, 0xdd, 0x5d, 0x3f, 0x8c, 0x76,
            0x23, 0x04, 0x8c, 0x9c, 0x06, 0x3d, 0x53, 0x2c,
            0xc9, 0x5c, 0x5e, 0xd7, 0xa8, 0x98, 0xa6, 0x4f };
    unsigned int  ucExpectedLen = 32;
    int rv = CY_Hash(SGD_SHA256, pucInData, uiInDataLen, pucOutData, &puiOutDataLen);
    ASSERT_EQ(rv, 0);
    ASSERT_EQ(puiOutDataLen, ucExpectedLen);
    EXPECT_TRUE(std::memcmp(pucOutData, ucExpected, puiOutDataLen) == 0);
}

TEST(HashTest, SHA256UpdateTest) {
    unsigned char pucInData[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    unsigned int uiInDataLen  = sizeof(pucInData);
    unsigned char pucOutData[32] = {0};
    unsigned int  puiOutDataLen  = 32;
    unsigned char ucExpected[32] = {
            0xef, 0x79, 0x7c, 0x81, 0x18, 0xf0, 0x2d, 0xfb,
            0x64, 0x96, 0x07, 0xdd, 0x5d, 0x3f, 0x8c, 0x76,
            0x23, 0x04, 0x8c, 0x9c, 0x06, 0x3d, 0x53, 0x2c,
            0xc9, 0x5c, 0x5e, 0xd7, 0xa8, 0x98, 0xa6, 0x4f };
    unsigned int  ucExpectedLen = 32;
    void *phHashObj = nullptr;
    int rv = CY_CreateHashObj(&phHashObj, SGD_SHA256);
    ASSERT_EQ(rv, 0);
    rv = CY_HashUpdate(phHashObj, pucInData, uiInDataLen);
    ASSERT_EQ(rv, 0);
    rv = CY_HashFinal(phHashObj, pucOutData, &puiOutDataLen);
    ASSERT_EQ(rv, 0);
    CY_DestroyHashObj(phHashObj);
    ASSERT_EQ(puiOutDataLen, ucExpectedLen);
    EXPECT_TRUE(std::memcmp(pucOutData, ucExpected, puiOutDataLen) == 0);
}


TEST(HashTest, SHA512Test) {
    unsigned char pucInData[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    unsigned int uiInDataLen  = sizeof(pucInData);
    unsigned char pucOutData[64] = {0};
    unsigned int  puiOutDataLen  = 64;
    unsigned char ucExpected[64] = {
            0xfa, 0x58, 0x5d, 0x89, 0xc8, 0x51, 0xdd, 0x33,
            0x8a, 0x70, 0xdc, 0xf5, 0x35, 0xaa, 0x2a, 0x92,
            0xfe, 0xe7, 0x83, 0x6d, 0xd6, 0xaf, 0xf1, 0x22,
            0x65, 0x83, 0xe8, 0x8e, 0x09, 0x96, 0x29, 0x3f,
            0x16, 0xbc, 0x00, 0x9c, 0x65, 0x28, 0x26, 0xe0,
            0xfc, 0x5c, 0x70, 0x66, 0x95, 0xa0, 0x3c, 0xdd,
            0xce, 0x37, 0x2f, 0x13, 0x9e, 0xff, 0x4d, 0x13,
            0x95, 0x9d, 0xa6, 0xf1, 0xf5, 0xd3, 0xea, 0xbe };
    unsigned int  ucExpectedLen = 64;
    int rv = CY_Hash(SGD_SHA512, pucInData, uiInDataLen, pucOutData, &puiOutDataLen);
    ASSERT_EQ(rv, 0);
    ASSERT_EQ(puiOutDataLen, ucExpectedLen);
    EXPECT_TRUE(std::memcmp(pucOutData, ucExpected, puiOutDataLen) == 0);
}

TEST(HashTest, SHA512UpdateTest) {
    unsigned char pucInData[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    unsigned int uiInDataLen  = sizeof(pucInData);
    unsigned char pucOutData[64] = {0};
    unsigned int  puiOutDataLen  = 64;
    unsigned char ucExpected[64] = {
            0xfa, 0x58, 0x5d, 0x89, 0xc8, 0x51, 0xdd, 0x33,
            0x8a, 0x70, 0xdc, 0xf5, 0x35, 0xaa, 0x2a, 0x92,
            0xfe, 0xe7, 0x83, 0x6d, 0xd6, 0xaf, 0xf1, 0x22,
            0x65, 0x83, 0xe8, 0x8e, 0x09, 0x96, 0x29, 0x3f,
            0x16, 0xbc, 0x00, 0x9c, 0x65, 0x28, 0x26, 0xe0,
            0xfc, 0x5c, 0x70, 0x66, 0x95, 0xa0, 0x3c, 0xdd,
            0xce, 0x37, 0x2f, 0x13, 0x9e, 0xff, 0x4d, 0x13,
            0x95, 0x9d, 0xa6, 0xf1, 0xf5, 0xd3, 0xea, 0xbe };
    unsigned int  ucExpectedLen = 64;
    void *phHashObj = nullptr;
    int rv = CY_CreateHashObj(&phHashObj, SGD_SHA512);
    ASSERT_EQ(rv, 0);
    rv = CY_HashUpdate(phHashObj, pucInData, uiInDataLen);
    ASSERT_EQ(rv, 0);
    rv = CY_HashFinal(phHashObj, pucOutData, &puiOutDataLen);
    ASSERT_EQ(rv, 0);
    CY_DestroyHashObj(phHashObj);
    ASSERT_EQ(puiOutDataLen, ucExpectedLen);
    EXPECT_TRUE(std::memcmp(pucOutData, ucExpected, puiOutDataLen) == 0);
}

TEST(HashTest, SM3Test) {
    unsigned char pucInData[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    unsigned int uiInDataLen  = sizeof(pucInData);
    unsigned char pucOutData[32] = {0};
    unsigned int  puiOutDataLen  = 32;
    unsigned char ucExpected[32] = {
            0x0f, 0xff, 0xff, 0x81, 0xe9, 0x71, 0xfa, 0x3f,
            0x09, 0x10, 0x7a, 0xbf, 0x77, 0x93, 0x14, 0x63,
            0xfc, 0x07, 0x10, 0xbf, 0xb8, 0x96, 0x2e, 0xfe,
            0xae, 0x3d, 0x56, 0x54, 0xb0, 0x73, 0xbb, 0x0c };
    unsigned int  ucExpectedLen = 32;
    int rv = CY_Hash(SGD_SM3, pucInData, uiInDataLen, pucOutData, &puiOutDataLen);
    ASSERT_EQ(rv, 0);
    ASSERT_EQ(puiOutDataLen, ucExpectedLen);
    EXPECT_TRUE(std::memcmp(pucOutData, ucExpected, puiOutDataLen) == 0);
}

TEST(HashTest, SM3UpdateTest) {
    unsigned char pucInData[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    unsigned int uiInDataLen  = sizeof(pucInData);
    unsigned char pucOutData[32] = {0};
    unsigned int  puiOutDataLen  = 32;
    unsigned char ucExpected[32] = {
            0x0f, 0xff, 0xff, 0x81, 0xe9, 0x71, 0xfa, 0x3f,
            0x09, 0x10, 0x7a, 0xbf, 0x77, 0x93, 0x14, 0x63,
            0xfc, 0x07, 0x10, 0xbf, 0xb8, 0x96, 0x2e, 0xfe,
            0xae, 0x3d, 0x56, 0x54, 0xb0, 0x73, 0xbb, 0x0c };
    unsigned char ucExpectedLen = 32;
    void *phHashObj = nullptr;
    int rv = CY_CreateHashObj(&phHashObj, SGD_SM3);
    ASSERT_EQ(rv, 0);
    rv = CY_HashUpdate(phHashObj, pucInData, uiInDataLen);
    ASSERT_EQ(rv, 0);
    rv = CY_HashFinal(phHashObj, pucOutData, &puiOutDataLen);
    ASSERT_EQ(rv, 0);
    CY_DestroyHashObj(phHashObj);
    ASSERT_EQ(puiOutDataLen, ucExpectedLen);
    EXPECT_TRUE(std::memcmp(pucOutData, ucExpected, puiOutDataLen) == 0);
}