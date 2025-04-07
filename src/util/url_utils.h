// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_URL_UTILS_H
#define CYBERLIB_BUILD_URL_UTILS_H

#include <string>

namespace cyber {

class UrlUtils {
public:
    static std::string EncodeUrl(const std::string & str);
    static std::string DecodeUrl(const std::string & str);
};

}


#endif //CYBERLIB_BUILD_URL_UTILS_H
