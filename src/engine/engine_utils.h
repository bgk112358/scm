// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_DRIVER_UTILS_H
#define CYBERLIB_BUILD_DRIVER_UTILS_H

#include <vector>
#include <openssl/err.h>
#include "plog/Log.h"

namespace cyber {

enum EngineSeverity
{
    NONE    = 0,
    FATAL   = 1,
    ERROR   = 2,
    WARNING = 3,
    INFO    = 4,
    DEBUG   = 5,
    VERBOSE = 6
};

#define ENGINE_LOG(level, message)          \
do {                                        \
    PLOG((plog::Severity)level) << message; \
} while(0)

class RsaUtils {
public:
    static std::vector<unsigned char> EncodeDigestInfo(
            int nid, const std::vector<unsigned char> &sSrc);
};

class ErrorUtils {
public:
    static void PutError();
};

class EngineHexUtils{
    public:
    static std::string EncodeStr(const unsigned char *sStr, unsigned int iLen);
};
}


#endif //CYBERLIB_BUILD_DRIVER_UTILS_H
