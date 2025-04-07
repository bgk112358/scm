// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "file_utils.h"
#include <dirent.h>
#include <sys/stat.h>
#include <cstring>

#define PERMISSION_0750  (S_IRWXU | S_IRGRP | S_IXGRP)
#define PERMISSION_0640  (S_IRUSR | S_IWUSR | S_IRGRP)

using namespace cyber;

bool FileUtils::IsExist(const std::string &sPath) {
    struct stat tStat = {0};
    int ret = stat(sPath.c_str(), &tStat);
    if (ret == 0) {
        return true;
    }
    return false;
}

int FileUtils::IsDir(const std::string &sPath, bool &bIsDir) {
    bIsDir = false;
    struct stat tStat = {0};
    int ret = stat(sPath.c_str(), &tStat);
    if (ret != 0)
    {
        return ret;
    }

    if (tStat.st_mode & S_IFDIR)
    {
        bIsDir = true;
    }

    return 0;
}

int FileUtils::CreateDir(const std::string &sDirPath) {
    int ret = mkdir(sDirPath.c_str(), PERMISSION_0750);
    if (ret == -1)
    {
        return ret;
    }

    return 0;
}

int FileUtils::DeleteDir(const std::string &sDirPath) {
    DIR * dir = nullptr;
    struct dirent  * ptr;

    dir = opendir(sDirPath.c_str());
    if (dir == nullptr)
    {
        return 0;
    }

    int ret = 0;
    while ((ptr = readdir(dir)) != nullptr)
    {
        if (strcmp(ptr->d_name, ".") == 0
            || strcmp(ptr->d_name, "..") == 0)
        {
            continue;
        }

        char sChildPath[1024] = {0};
        snprintf(sChildPath, sizeof(sChildPath), "%s/%s", sDirPath.c_str(), ptr->d_name);

        bool bIsDir = false;
        ret = FileUtils::IsDir(sChildPath, bIsDir);
        if (ret != 0)
        {
            break;
        }

        if (bIsDir)
        {
            ret = DeleteDir(sChildPath);
            if (ret != 0)
            {
                break;
            }
        }
        else
        {
            ret = remove(sChildPath);
            if (ret != 0)
            {
                break;
            }
        }
    }

    closedir(dir);

    if (ret == 0)
    {
        ret = remove(sDirPath.c_str());
    }

    return ret;
}

int FileUtils::IterDir(const std::string &sDirPath,
                       std::vector<std::string> &vecFilePathList) {
    DIR * dir = nullptr;
    struct dirent  * ptr;

    dir = opendir(sDirPath.c_str());
    if (dir == nullptr)
    {
        return 0;
    }


    int ret = 0;
    while ((ptr = readdir(dir)) != nullptr)
    {
        if (strcmp(ptr->d_name, ".") == 0
            || strcmp(ptr->d_name, "..") == 0)
        {
            continue;
        }

        char sChildPath[1024] = {0};
        snprintf(sChildPath, sizeof(sChildPath), "%s/%s", sDirPath.c_str(), ptr->d_name);

        bool bIsDir = false;
        ret = FileUtils::IsDir(sChildPath, bIsDir);
        if (ret != 0)
        {
            break;
        }

        if (bIsDir)
        {
            ret = IterDir(sChildPath, vecFilePathList);
            if (ret != 0)
            {
                break;
            }
        }
        else
        {
            vecFilePathList.emplace_back(sChildPath);
        }
    }

    closedir(dir);

    return ret;
}

int FileUtils::DeleteFile(const std::string &sFilePath) {
    return remove(sFilePath.c_str());
}
