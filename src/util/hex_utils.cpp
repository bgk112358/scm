// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "hex_utils.h"
#include <sstream>

using namespace cyber;

std::string HexUtils::EncodeNumber(unsigned int iNum) {
    std::ostringstream oss;
    oss << std::hex << iNum;
    std::string hexString = oss.str();
    return hexString;
}

std::string HexUtils::EncodeStr(const unsigned char *sStr, unsigned int iLen) {
    std::string s;
    char buf[3] = {0};
    if (sStr == nullptr || iLen == 0) {
        return "";
    }
    for (unsigned int i = 0; i < iLen; ++i) {
        snprintf(buf, sizeof(buf), "%02x", sStr[i]);
        s.append(buf);
    }
    return s;
}

std::string HexUtils::DecodeStr(const char *sStr, unsigned int iLen) {
    std::string s(sStr);
    std::string ret;
    if (sStr == nullptr || iLen == 0) {
        return "";
    }
    if (iLen % 2 != 0) {
        return "";
    }
    for (size_t i = 0; i < iLen; i += 2) {
        std::string buffer = s.substr(i, 2);
        auto byte = static_cast<char>(std::stoul(buffer, nullptr, 16));
        ret.push_back(byte);
    }
    return ret;
}

