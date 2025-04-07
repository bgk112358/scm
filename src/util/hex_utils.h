// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_HEX_UTILS_H
#define CYBERLIB_BUILD_HEX_UTILS_H

#include <string>

namespace cyber {
class HexUtils {
public:
    static std::string EncodeNumber(unsigned int iNum);

    static std::string EncodeStr(const unsigned char *sStr, unsigned int iLen);

    static std::string DecodeStr(const char *sStr, unsigned int iLen);
    
};
}

#endif //CYBERLIB_BUILD_HEX_UTILS_H
