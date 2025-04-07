// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//

#include "gtest/gtest.h"

#ifdef __cplusplus
extern "C" {
#include "cyber_pki.h"
}
#endif

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    void *hAppHandle = nullptr;
    int rv = CY_InitService(&hAppHandle,
                            "./cyber");
    printf("IW_InitService: %02x\n", rv);
    return RUN_ALL_TESTS();
}