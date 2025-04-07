// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_IO_UTILS_H
#define CYBERLIB_BUILD_IO_UTILS_H

#include <string>
#include <vector>

namespace cyber {
class IoUtils {
public:
    // Write File
    static bool WriteFile(const std::string &sFileName,
                          const std::vector<unsigned char> &vData);
    static bool WriteFile(const std::string &sFileName,
                          const unsigned char *ucData,
                          unsigned int uiDataLen);

    // Read File
    static bool ReadFile(const std::string &sFileName,
                         std::vector<unsigned char> &vData);
};
}


#endif //CYBERLIB_BUILD_IO_UTILS_H
