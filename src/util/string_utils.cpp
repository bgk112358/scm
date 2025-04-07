// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "string_utils.h"
#include <algorithm>
#include <cstring>

using namespace cyber;

bool StringUtils::isEmpty(const char *sChar) {
    if (sChar == nullptr) return true;
    if (strlen(sChar) == 0) return true;
    return false;
}

bool StringUtils::StartWith(const std::string &sStr, const std::string &sHead) {
    if (sHead.size() > sStr.size())
    {
        return false;
    }
    if (sStr.compare(0, sHead.size(), sHead) != 0)
    {
        return false;
    }
    return true;
}

bool StringUtils::EndWith(const std::string &sStr, const std::string &sTail) {
    if (sTail.size() > sStr.size())
    {
        return false;
    }
    if (sStr.compare(sStr.size() - sTail.size(), sTail.size(), sTail) != 0)
    {
        return false;
    }
    return true;
}

bool StringUtils::ContainWith(const std::string &sStr, const std::string &sDst) {
    if (sDst.empty())
    {
        return false;
    }
    if (sDst.size() > sStr.size())
    {
        return false;
    }
    return (sStr.find(sDst) != -1);
}

bool StringUtils::ContainIgnoreCaseWith(const std::string & sStr, const std::string & sDst) {
    std::string sStrUpper = StringUtils::UpperAscii(sStr);
    std::string sDstUpper = StringUtils::UpperAscii(sDst);
    return StringUtils::ContainWith(sStrUpper, sDstUpper);
}

std::string StringUtils::UpperAscii(const std::string &sStr) {
    std::string s(sStr);
    std::transform(s.begin(), s.end(), s.begin(), toupper);
    return s;
}

std::string StringUtils::LowerAscii(const std::string &sStr) {
    std::string s(sStr);
    std::transform(s.begin(), s.end(), s.begin(), tolower);
    return s;
}

std::string StringUtils::ReplaceStr(const std::string &sStr,
                                    const std::string &sOrg,
                                    const std::string &sTar) {
    std::string s(sStr);
    size_t pos = s.find(sOrg);
    if (pos != std::string::npos) {
        s.replace(pos, sOrg.length(), sTar);
    }
    return s;
}

