// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "io_utils.h"
#include <cstring>
#include <openssl/bio.h>
#include <openssl/err.h>

using namespace cyber;

bool
IoUtils::WriteFile(const std::string &sFileName,
                   const std::vector<unsigned char> &vData) {
    BIO *bio = BIO_new_file(sFileName.c_str(), "wb");
    if (bio == nullptr) {
        return false;
    }
    auto *ucData = (unsigned char *)OPENSSL_zalloc(vData.size() + 1);
    unsigned int uiDataLen = vData.size();
    if (ucData) {
        memcpy(ucData, vData.data(), vData.size());
    }
    int len = BIO_write(bio, ucData, (int)uiDataLen);
    if (len != (int)vData.size()) {
        BIO_free(bio);
        return false;
    }
    BIO_free(bio);
    OPENSSL_free(ucData);
    return true;
}

bool
IoUtils::WriteFile(const std::string &sFileName,
                   const unsigned char *ucData,
                   unsigned int uiDataLen) {
    if (ucData == nullptr || uiDataLen == 0) {
        return false;
    }
    std::vector<unsigned char> vData(ucData, ucData + uiDataLen);
    return WriteFile(sFileName, vData);
}


bool
IoUtils::ReadFile(const std::string &sFileName,
                  std::vector<unsigned char> &vData) {
    char buffer[2048] = {0};
    int buffer_len;
    std::string result;
    BIO *bio = BIO_new_file(sFileName.c_str(), "rb");
    if (bio == nullptr) {
        ERR_print_errors_fp(stderr);
        return false;
    }
    vData.clear();
    while ((buffer_len = BIO_read(bio, buffer, sizeof(buffer))) > 0) {
        for (int i = 0; i < buffer_len; ++i) {
            vData.push_back(buffer[i]);
        }
    }
    BIO_free(bio);
    return true;
}


