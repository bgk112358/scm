// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//
#ifndef SVKD_BUILD_OPENSSL_UTIL_H
#define SVKD_BUILD_OPENSSL_UTIL_H

#include <string>
#include <openssl/err.h>
#include "status_util.h"
#include "plog/Log.h"

namespace cyber {

class OpensslUtils {
public:
    static unsigned long GetErrCode();
    static std::string GetErrMsg();
    static void ClearErr();
    static bool ReadBio(BIO *pBio, std::string& sStr);
};

}

#define LOGM_OPENSSL_LOG(level, message)          \
do {                                        \
    PLOG((plog::Severity)level) << message; \
} while(0)

static void Openssl_error_clear() {
    cyber::OpensslUtils::ClearErr();
}

static int Openssl_error(const char *aString) {
    int err;
    std::string sString = cyber::OpensslUtils::GetErrMsg();
    err = (int)cyber::OpensslUtils::GetErrCode();
    LOGE << aString << " Msg: " << sString << "";
    return err;
}

#define LOGM_OPENSSL_ERRORS()                  \
do{                                            \
    LOGE << cyber::OpensslUtils::GetErrMsg();  \
    cyber::OpensslUtils::ClearErr();           \
} while (0)

#endif //SVKD_BUILD_OPENSSL_UTIL_H
