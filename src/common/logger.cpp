// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "logger.h"
#include "plog/Log.h"
#include "plog/Initializers/RollingFileInitializer.h"

using namespace cyber;

Logger::Logger()
    : isInit_(false)
{
    
}

Logger::~Logger()
{
    isInit_ = false;
}

Logger *Logger::Instance()
{
    static Logger oLogger;
    return &oLogger;
}

void Logger::InitLogger(LoggerSeverity severity, std::string &path)
{
    if (!isInit_) {
          plog::init((plog::Severity)severity, path.c_str(), 1048576, 1);
    }
    isInit_ = true;
}


