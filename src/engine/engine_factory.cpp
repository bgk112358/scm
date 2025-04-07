// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "engine_factory.h"
#include "engine_utils.h"
#include "cyber/catarc_engine.h"

typedef enum  {
    ENGINE_NONE            = 0,
    ENGINE_CATARC          = 1
} EngineType;

using namespace cyber;


#if defined(ENABLE_CATARC_ENGINE)
static EngineType driverType = ENGINE_CATARC;
#else
static EngineType driverType = ENGINE_NONE;
#endif

using namespace cyber;

std::unique_ptr<IEngine> EngineFactory::Create() {
    std::unique_ptr<IEngine> iEngine = nullptr;
    switch (driverType) {
        case ENGINE_NONE:
            break;
        case ENGINE_CATARC:
            
            iEngine = std::unique_ptr<IEngine>(new CatarcEngine());
            break;
        default:
            iEngine = nullptr;
            break;
    }
    return iEngine;
}

int EngineFactory::Login(
        unsigned int uiUsrType, unsigned char *pucContainerName,
        unsigned int uiContainerNameLen, unsigned char *pucPin,
        unsigned int uiPinLen, unsigned int *puiRemainCount) {
    int rv = -1;
    if (pucContainerName == nullptr) {
        ENGINE_LOG(ERROR, "Container or Pin input error.");
        return rv;
    }
    std::unique_ptr<IEngine> driver = EngineFactory::Create();
    if (driver == nullptr) {
        ENGINE_LOG(ERROR, "Create fail.");
        return rv;
    }
    rv = driver->Initialize();
    if (rv != 0) {
        ENGINE_LOG(ERROR, "Initialize fail, fail code: " << rv);
        return rv;
    }
    rv = driver->Login(
            uiUsrType,
            pucContainerName,
            uiContainerNameLen,
            pucPin,
            uiPinLen,
            puiRemainCount);
    if (rv != 0) {
        ENGINE_LOG(ERROR, "Login fail, fail code: " << rv);
        return -1;
    }
    return rv;
}

int EngineFactory::Logout(unsigned int uiUsrType) {
    std::unique_ptr<IEngine> driver = EngineFactory::Create();
    if (driver == nullptr) {
        ENGINE_LOG(ERROR, "Create fail.");
        return -1;
    }
    int rv = driver->Logout(uiUsrType);
    if (rv != 0) {
        ENGINE_LOG(ERROR, "Logout fail, fail code: " << rv);
        return -1;
    }
    rv = driver->Finalize();
    if (rv != 0) {
        ENGINE_LOG(ERROR, "Finalize fail, fail code: " << rv);
        return -1;
    }
    return rv;
}
