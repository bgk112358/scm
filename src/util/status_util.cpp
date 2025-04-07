//
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//

#include "status_util.h"

namespace cyber {
namespace util {

Status::Status() {
    code_ = error::Code::Ok;
    message_ = "";
}

Status::Status(int code, const std::string &error_message) {
    code_ = code;
    message_ = error_message;
    if (code == error::Code::Ok) {
        message_.clear();
    }
}

Status::Status(const Status &other) {
    code_ = other.code_;
    message_ = other.message_;
}

Status &Status::operator=(const Status &other) = default;

}
}