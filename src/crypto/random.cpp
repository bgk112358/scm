// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//

#include "random.h"
#include <openssl/rand.h>
#include <cstdint>

namespace cyber {

void RandBytes(void *bytes, size_t length) {
    if (bytes == nullptr) return;
    RAND_bytes((unsigned char *)bytes, (int)length);
}

void RandBytes(std::vector<unsigned char>& bytes) {
    RandBytes((unsigned char *)bytes.data(), (int)bytes.size());
}

std::string RandString(size_t length) {
    std::string ret;
    ret.resize(length);
    RandBytes((void *)ret.data(), (size_t)ret.size());
    return ret;
}

std::string RandHexString(size_t length) {
    std::string ret;
    std::vector<unsigned char> rand;
    rand.resize(length);
    RandBytes(rand.data(), (int)rand.size());
    char buf[3] = {0};
    if (rand.empty()) {
        return "";
    }
    for (auto&& e : rand) {
        auto index = static_cast<std::uint8_t>(e);
        snprintf(buf, sizeof(buf), "%02x", index);
        ret.append(buf);
    }
    return ret;
}

}