// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_STRING_UTILS_H
#define CYBERLIB_BUILD_STRING_UTILS_H

#include <string>

namespace cyber {

class StringUtils {
public:

    static bool isEmpty(const char *sChar);

    static bool StartWith(const std::string & sStr, const std::string & sHead);
    static bool EndWith(const std::string & sStr, const std::string & sTail);

    static bool ContainWith(const std::string & sStr, const std::string & sDst);
    static bool ContainIgnoreCaseWith(const std::string & sStr, const std::string & sDst);

    static std::string UpperAscii(const std::string & sStr);
    static std::string LowerAscii(const std::string & sStr);
    static std::string ReplaceStr(const std::string & sStr, const std::string & sOrg, const std::string & sTar);

};

}

#endif //CYBERLIB_BUILD_STRING_UTILS_H
