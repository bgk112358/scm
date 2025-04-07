// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_CONTAINER_BUILDER_H
#define CYBERLIB_BUILD_CONTAINER_BUILDER_H

#include <memory>
#include <string>
#include <vector>
#include "container.h"

namespace cyber {

class ContainerBuilder {

public:
    ContainerBuilder() {
        container_ = std::unique_ptr<Container>(new Container());
    }

    ContainerBuilder& SetVersion(unsigned int version) {
        container_->SetContainerVersion(version);
        return *this;
    }

    ContainerBuilder& SetStorageType(Container::StorageType storageType) {
        container_->SetContainerType(storageType);
        return *this;
    }

    ContainerBuilder& SetContainerName(const std::string& containerName) {
        container_->SetContainerName(containerName);
        return *this;
    }

    ContainerBuilder& SetUsage(Container::Usage usage) {
        container_->SetContainerUsage(usage);
        return *this;
    }

    ContainerBuilder& SetExportFlag(unsigned int exportFlag) {
        container_->SetContainerExportFlag(exportFlag);
        return *this;
    }

    ContainerBuilder& SetAlgorithm(Container::Algorithm algorithm) {
        container_->SetAlgorithmIdentify(algorithm);
        return *this;
    }

    ContainerBuilder& SetContainerPin(const std::string& containerPin) {
        container_->containerPin_ = containerPin;
        return *this;
    }

    ContainerBuilder& SetOriginalData(const std::vector<unsigned char>& vOrgData) {
        container_->vOrgData = vOrgData;
        return *this;
    }

    std::unique_ptr<Container> build() {
        if (!container_->BuildContainer()) {
            return nullptr;
        }
        return std::move(container_);
    }

private:
    std::unique_ptr<Container> container_;
};

}


#endif //CYBERLIB_BUILD_CONTAINER_BUILDER_H
