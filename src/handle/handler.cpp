// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "handler.h"
#include "util/util.h"
#include "common/logger.h"
#include "util/path_utils.h"

#if defined(ENABLE_DRIVER)
#include "cyber_engine.h"
#endif

using namespace cyber;

Handler::Handler()
    : isInitialized_(false)
{

}

Handler::~Handler() {
    isInitialized_ = false;
    isHardWare_ = false;
}

Handler *Handler::Instance() {
    static Handler oHandler;
    return &oHandler;
}

bool Handler::Initialize() {
    // Create folder
    if (!FileUtils::IsExist(folder_name_)) {
        int ret = FileUtils::CreateDir(folder_name_);
        if (ret != 0) {
            fprintf(stderr, "CreateDir %s fail %s\n", folder_name_.c_str(), strerror(errno));
            isInitialized_ = false;
            return false;
        }
    }
    // Log info
    std::string logString = PathUtils::JoinPath(folder_name_, "cyber.log");
    Logger::Instance()->InitLogger(Logger::LoggerSeverity::DEBUG, logString);

    // Engine
#if defined(ENABLE_DRIVER)
    isHardWare_ = true;
    if (!isInitialized_) {
        ENGINE_load_cyber();
    }
#endif
    // Config info
    isInitialized_ = true;
    return true;
}

bool Handler::UnInitialize() {
#if defined(ENABLE_DRIVER)
    if (isInitialized_ &&
        isHardWare_) {
        ENGINE_unload_cyber();
    }
#endif
    isInitialized_ = false;
    return false;
}
