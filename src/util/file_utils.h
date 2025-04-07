// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_FILE_UTILS_H
#define CYBERLIB_BUILD_FILE_UTILS_H

#include <string>
#include <vector>

namespace cyber {
class FileUtils {
public:
    static bool IsExist(const std::string & sPath);

    static int IsDir(const std::string & sPath, bool & bIsDir);

    static int CreateDir(const std::string & sDirPath);

    static int DeleteDir(const std::string & sDirPath);

    static int DeleteFile(const std::string& sFilePath);

    static int IterDir(const std::string & sDirPath, std::vector<std::string> & vecFilePathList);
};
}


#endif //CYBERLIB_BUILD_FILE_UTILS_H
