// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//

#include "base64.h"
#include <openssl/evp.h>

namespace cyber {

std::string Base64Encode(const std::string &from) {
    int rv;
    std::string ret;
    if (from.empty()) {
        return "";
    }
    auto size = (int)(4 * ((from.size() + 2) / 3));
    ret.resize(size + 1);
    rv = EVP_EncodeBlock((unsigned char *)ret.data(),
                         (const unsigned char *)from.data(),
                         (int)from.size());
    if (size != rv) {
        return "";
    }
    ret.pop_back();
    return ret;
}

std::string Base64Encode(const unsigned char *from, unsigned int len) {
    int rv;
    std::string ret;
    if (!from || !len) {
        return "";
    }
    auto size = (int)(4 * ((len + 2) / 3));
    ret.resize(size + 1);
    rv = EVP_EncodeBlock((unsigned char *)ret.data(),
                         from,
                         (int)len);
    if (size != rv) {
        return "";
    }
    ret.pop_back();
    return ret;
}

std::vector<unsigned char> Base64Decode(const std::string &from) {
    int rv;
    std::vector<unsigned char> ret;
    if (from.size() < 3) {
        if (from.empty()) {
            return {};
        }
        return {};
    }
    auto size = (int)(3 * from.size() / 4);
    ret.resize(size + 1);
    rv = EVP_DecodeBlock((unsigned char*)(ret.data()),
                         (const unsigned char*)(from.data()),
                         (int)from.size());
    if (rv != size) {
        return {};
    }
    if (from[from.size() - 1] == '=') {
        ret.pop_back();
    }
    if (from[from.size() - 2] == '=') {
        ret.pop_back();
    }
    ret.pop_back();
    return ret;
}

std::vector<unsigned char> Base64Decode(
        const unsigned char *from, unsigned int len) {
    int rv;
    std::vector<unsigned char> ret;

    if (len < 3) {
        if (from == nullptr) {
            return {};
        }
        return {};
    }

    auto size = (int)(3 * len / 4);
    ret.resize(size + 1);
    rv = EVP_DecodeBlock((unsigned char*)(ret.data()),
                         (const unsigned char*)from,
                         (int)len);
    if (rv != size) {
        return {};
    }

    if (from[len - 1] == '=') {
        ret.pop_back();
    }
    if (from[len - 2] == '=') {
        ret.pop_back();
    }
    ret.pop_back();
    return ret;
}

}