// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_LOGGER_H
#define CYBERLIB_BUILD_LOGGER_H

#include <string>

namespace cyber {

class Logger {
public:
    typedef enum {
        NONE    = 0,
        FATAL   = 1,
        ERROR   = 2,
        WARNING = 3,
        INFO    = 4,
        DEBUG   = 5,
        VERBOSE = 6
    } LoggerSeverity;

    Logger();
    ~Logger();

    static Logger *Instance();

    void InitLogger(LoggerSeverity severity, std::string & path);

private:
    bool isInit_ = false;

};

}


#endif //CYBERLIB_BUILD_LOGGER_H
