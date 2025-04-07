// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_ENGINE_FACTORY_H
#define CYBERLIB_BUILD_ENGINE_FACTORY_H

#include "iengine.h"
#include <memory>

namespace cyber {
class EngineFactory {
public:
    static std::unique_ptr<IEngine> Create();

    static int Login(
            unsigned int uiUsrType,
            unsigned char *pucContainerName,
            unsigned int uiContainerNameLen,
            unsigned char *pucPin,
            unsigned int uiPinLen,
            unsigned int *puiRemainCount);

    static int Logout(unsigned int uiUsrType);

};

}

#endif //CYBERLIB_BUILD_ENGINE_FACTORY_H
