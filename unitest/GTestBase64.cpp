// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//

#include "gtest/gtest.h"
#include <cstring>
extern "C" {
#include "cyber_pki.h"
}

TEST(Base64Test, EncodingTest1) {
    unsigned char ucInData[] = "";
    unsigned int  uiInDataLen = 0;
    unsigned char ucOutData[128] = {0};
    unsigned int  uiOutDataLen = 128;
    int rv = CY_Base64_Encode(ucInData, uiInDataLen, ucOutData, &uiOutDataLen);
    ASSERT_EQ(rv, 0);
    EXPECT_TRUE(uiOutDataLen == 0);
}

TEST(Base64Test, EncodingTest2) {
    unsigned char ucInData[] = "a";
    unsigned int  uiInDataLen = strlen((char *)ucInData);
    unsigned char ucOutData[128] = {0};
    unsigned int  uiOutDataLen = 128;
    unsigned char ucExpected[] = "YQ==";
    int rv = CY_Base64_Encode(ucInData, uiInDataLen, ucOutData, &uiOutDataLen);
    ASSERT_EQ(rv, 0);
    EXPECT_TRUE(std::memcmp(ucOutData, ucExpected, uiOutDataLen) == 0);
}

TEST(Base64Test, EncodingTest3) {
    unsigned char ucInData[] = "Hello, world!";
    unsigned int  uiInDataLen = strlen((char *)ucInData);
    unsigned char ucOutData[128] = {0};
    unsigned int  uiOutDataLen = 128;
    unsigned char ucExpected[] = "SGVsbG8sIHdvcmxkIQ==";
    int rv = CY_Base64_Encode(ucInData, uiInDataLen, ucOutData, &uiOutDataLen);
    ASSERT_EQ(rv, 0);
    EXPECT_TRUE(std::memcmp(ucOutData, ucExpected, uiOutDataLen) == 0);
}

TEST(Base64Test, EncodingTest4) {
    unsigned char ucInData[] = "123";
    unsigned int  uiInDataLen = strlen((char *)ucInData);
    unsigned char ucOutData[128] = {0};
    unsigned int  uiOutDataLen = 128;
    unsigned char ucExpected[] = "MTIz";
    int rv = CY_Base64_Encode(ucInData, uiInDataLen, ucOutData, &uiOutDataLen);
    ASSERT_EQ(rv, 0);
    EXPECT_TRUE(std::memcmp(ucOutData, ucExpected, uiOutDataLen) == 0);
}

TEST(Base64Test, EncodingTest5) {
    unsigned char ucInData[] = "1234";
    unsigned int  uiInDataLen = strlen((char *)ucInData);
    unsigned char ucOutData[128] = {0};
    unsigned int  uiOutDataLen = 128;
    unsigned char ucExpected[] = "MTIzNA==";
    int rv = CY_Base64_Encode(ucInData, uiInDataLen, ucOutData, &uiOutDataLen);
    ASSERT_EQ(rv, 0);
    EXPECT_TRUE(std::memcmp(ucOutData, ucExpected, uiOutDataLen) == 0);
}

TEST(Base64Test, EncodingTest6) {
    unsigned char ucInData[] = "$%^&*";
    unsigned int  uiInDataLen = strlen((char *)ucInData);
    unsigned char ucOutData[128] = {0};
    unsigned int  uiOutDataLen = 128;
    unsigned char ucExpected[] = "JCVeJio=";
    int rv = CY_Base64_Encode(ucInData, uiInDataLen, ucOutData, &uiOutDataLen);
    ASSERT_EQ(rv, 0);
    EXPECT_TRUE(std::memcmp(ucOutData, ucExpected, uiOutDataLen) == 0);
}

TEST(Base64Test, DecodingTest1) {
    unsigned char ucInData[] = "";
    unsigned int  uiInDataLen = 0;
    unsigned char ucOutData[128] = {0};
    unsigned int  uiOutDataLen = 128;
    int rv = CY_Base64_Decode(ucInData, uiInDataLen, ucOutData, &uiOutDataLen);
    ASSERT_EQ(rv, 0);
    EXPECT_TRUE(uiOutDataLen == 0);
}

TEST(Base64Test, DecodingTest2) {
    unsigned char ucInData[] = "YQ==";
    unsigned int  uiInDataLen = strlen((char *)ucInData);
    unsigned char ucOutData[128] = {0};
    unsigned int  uiOutDataLen = 128;
    unsigned char ucExpected[] = "a";
    int rv = CY_Base64_Decode(ucInData, uiInDataLen, ucOutData, &uiOutDataLen);
    ASSERT_EQ(rv, 0);
    EXPECT_TRUE(std::memcmp(ucOutData, ucExpected, uiOutDataLen) == 0);
}

TEST(Base64Test, DecodingTest3) {
    unsigned char ucInData[] = "SGVsbG8sIHdvcmxkIQ==";
    unsigned int  uiInDataLen = strlen((char *)ucInData);
    unsigned char ucOutData[128] = {0};
    unsigned int  uiOutDataLen = 128;
    unsigned char ucExpected[] = "Hello, world!";
    int rv = CY_Base64_Decode(ucInData, uiInDataLen, ucOutData, &uiOutDataLen);
    ASSERT_EQ(rv, 0);
    EXPECT_TRUE(std::memcmp(ucOutData, ucExpected, uiOutDataLen) == 0);
}

TEST(Base64Test, DecodingTest4) {
    unsigned char ucInData[] = "MTIz";
    unsigned int  uiInDataLen = strlen((char *)ucInData);
    unsigned char ucOutData[128] = {0};
    unsigned int  uiOutDataLen = 128;
    unsigned char ucExpected[] = "123";
    int rv = CY_Base64_Decode(ucInData, uiInDataLen, ucOutData, &uiOutDataLen);
    ASSERT_EQ(rv, 0);
    EXPECT_TRUE(std::memcmp(ucOutData, ucExpected, uiOutDataLen) == 0);
}

TEST(Base64Test, DecodingTest5) {
    unsigned char ucInData[] = "MTIzNA==";
    unsigned int  uiInDataLen = strlen((char *)ucInData);
    unsigned char ucOutData[128] = {0};
    unsigned int  uiOutDataLen = 128;
    unsigned char ucExpected[] = "1234";
    int rv = CY_Base64_Decode(ucInData, uiInDataLen, ucOutData, &uiOutDataLen);
    ASSERT_EQ(rv, 0);
    EXPECT_TRUE(std::memcmp(ucOutData, ucExpected, uiOutDataLen) == 0);
}

TEST(Base64Test, DecodingTest6) {
    unsigned char ucInData[] = "JCVeJio=";
    unsigned int  uiInDataLen = strlen((char *)ucInData);
    unsigned char ucOutData[128] = {0};
    unsigned int  uiOutDataLen = 128;
    unsigned char ucExpected[] = "$%^&*";
    int rv = CY_Base64_Decode(ucInData, uiInDataLen, ucOutData, &uiOutDataLen);
    ASSERT_EQ(rv, 0);
    EXPECT_TRUE(std::memcmp(ucOutData, ucExpected, uiOutDataLen) == 0);
}