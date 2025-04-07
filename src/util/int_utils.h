// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_INT_UTILS_H
#define CYBERLIB_BUILD_INT_UTILS_H

namespace cyber {

class IntUtils {
public:

    static void IntToBytes(int num, unsigned char *bytes);

    static int BytesToInt(const unsigned char *bytes);
};

}

#endif //CYBERLIB_BUILD_INT_UTILS_H
