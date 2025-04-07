// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_LOG_UTILS_H
#define CYBERLIB_BUILD_LOG_UTILS_H

#include "plog/Log.h"

template<typename T>
bool has_null_parameter(T arg) {
    return arg == nullptr;
}

template<typename T, typename... Args>
bool has_null_parameter(T firstArg, Args... args) {
    return has_null_parameter(firstArg) || has_null_parameter(args...);
}

#define DCHECK_NUL(...)                        \
do {                                           \
    if (has_null_parameter(__VA_ARGS__)) {     \
        return cyber::error::Code::IndataErr;  \
    }                                          \
} while(0)


// Log record some information,
// Log call for global.

typedef enum {
    NONE    = 0,
    FATAL   = 1,
    ERROR   = 2,
    WARNING = 3,
    INFO    = 4,
    DEBUG   = 5,
    VERBOSE = 6
} MessageSeverity;

#define LOGM(level, message)                \
do {                                        \
    PLOG((plog::Severity)level) << message; \
} while(0)

template<typename T>
void log_parameter(std::ostringstream &oss, T t) {
    oss << t;
}

template<typename T, typename... Args>
void log_parameter(std::ostringstream &oss, T t, Args... args) {
    oss << t << ", ";
    log_parameter(oss, args...);
}

#define LOG_PARAMETER(par)   LOGM(INFO,  #par << ": " << par)
#define LOG_PARAMETERS(...)              \
do {                                     \
    std::ostringstream oss;              \
    log_parameter(oss, __VA_ARGS__);     \
    LOGM(INFO, oss.str());               \
} while(0)

// StackTrace
#define FUNC_ENTRY          LOGM(INFO, "> ")
#define FUNC_INFO(par)      LOGM(INFO, " - " << par)
#define FUNC_EXIT           LOGM(INFO, "< " << std::hex << rv)
#define FUNC_PARAMETER(par) LOGM(INFO,  #par << ": " << par)
#define FUNC_EXIT_RV(x)     LOGM(INFO, "< " << std::hex << "(" << rv << ")")

#endif //CYBERLIB_BUILD_LOG_UTILS_H
