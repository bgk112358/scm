// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_CONTAINER_RESOLVER_H
#define CYBERLIB_BUILD_CONTAINER_RESOLVER_H

#include <memory>
#include <vector>

#include "container.h"

namespace cyber {

static std::vector<unsigned char> vNullPin;

class ContainerResolver {

public:
    explicit ContainerResolver(const std::vector<unsigned char>& vInData);
    ~ContainerResolver();

    int Resolver(const std::vector<unsigned char>& vPinData);

    std::vector<unsigned char> GetPlainData();

    unsigned int GetVersion() const;
    unsigned int GetType() const;
    std::string GetName() const;
    unsigned int GetStatus() const;
    unsigned int GetUsage() const;
    unsigned int GetExportFlag() const;
    unsigned int GetAlgIdentify() const;

    std::string ToString() const;

private:
    std::vector<unsigned char> vInData_;
    std::vector<unsigned char> vPlainData_;
    unsigned int uiVersion_     = 0;
    unsigned int uiType_        = 0;
    std::string  sName_;
    unsigned int uiStatus_      = 0;
    unsigned int uiUsage_       = 0;
    unsigned int uiExportFlag_  = 0;
    unsigned int uiAlgIdentify_ = 0;
};

}


#endif //CYBERLIB_BUILD_CONTAINER_RESOLVER_H
