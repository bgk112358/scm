// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "url_utils.h"

using namespace cyber;

static unsigned char ToHex(unsigned char x)
{
    return  x > 9 ? x + 55 : x + 48;
}

static unsigned char FromHex(unsigned char x)
{
    unsigned char y = 0;
    if (x >= 'A' && x <= 'Z') y = x - 'A' + 10;
    else if (x >= 'a' && x <= 'z') y = x - 'a' + 10;
    else if (x >= '0' && x <= '9') y = x - '0';
    else y = y;
    return y;
}

std::string UrlUtils::EncodeUrl(const std::string &str) {
    std::string buffer;
    size_t length = str.length();

    if (str.empty() || length <= 0)
    {
        return "";
    }

    for (size_t i = 0; i < length; i++)
    {
        if (isalnum((unsigned char)str[i]) ||
            (str[i] == '-') ||
            (str[i] == '_') ||
            (str[i] == '.') ||
            (str[i] == '~'))
            buffer += str[i];
        else if (str[i] == ' ')
            buffer += "+";
        else
        {
            buffer += '%';
            buffer += (char)ToHex((unsigned char)str[i] >> 4);
            buffer += (char)ToHex((unsigned char)str[i] % 16);
        }
    }
    return buffer;
}

std::string UrlUtils::DecodeUrl(const std::string &str) {
    std::string sStr;
    size_t length = str.length();
    if (str.empty() || length <= 0)
    {
        return "";
    }
    for (size_t i = 0; i < length; i++)
    {
        if (str[i] == '+') sStr += ' ';
        else if (str[i] == '%')
        {
            if (i + 2 < length) break;
            unsigned char high = FromHex((unsigned char)str[++i]);
            unsigned char low = FromHex((unsigned char)str[++i]);
            sStr += std::to_string(high * 16 + low);
        }
        else sStr += str[i];
    }
    return sStr;
}
