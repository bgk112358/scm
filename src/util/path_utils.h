// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_PATH_UTILS_H
#define CYBERLIB_BUILD_PATH_UTILS_H

#include <string>
#include <cstring>

namespace cyber {

enum Ext {
    UNKNOWN,
    CERT_CHAIN,
    SIGN_CERT,
    SIGN_PUB_KEY,
    SIGN_KEY,
    ENC_CERT,
    ENC_PUB_KEY,
    ENC_KEY,
    CRL,
    CSR,
    UUID,
};

class PathUtils {
public:
      static std::string JoinPath(const std::string& sDir, const std::string & sFile);
      static std::string HashPath(const std::string& sDir, const std::string &identify, int ext);
};

}

#endif //CYBERLIB_BUILD_PATH_UTILS_H
