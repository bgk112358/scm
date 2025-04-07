// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//

#include "openssl_utils.h"
#include <openssl/evp.h>

using namespace cyber;

unsigned long OpensslUtils::GetErrCode() {
    return ERR_get_error();
}

std::string OpensslUtils::GetErrMsg() {
    if (ERR_peek_error() == 0)
        return "No OpenSSL errors left on stack";
    std::string stack_dump("OpenSSL errors left on stack:");
    unsigned long error;
    char error_string[256];
    while ((error = ERR_get_error()) != 0) {
        stack_dump.append("\n\t");
        ERR_error_string_n(error, error_string, 256);
        stack_dump.append(error_string);
    }
    return stack_dump;
}

void OpensslUtils::ClearErr() {
    ERR_clear_error();
}

bool OpensslUtils::ReadBio(BIO *pBio, std::string &sStr) {
    if (pBio == nullptr) {
        return false;
    }
    int size = BIO_pending(pBio);
    if (size == 0) {
        return true;
    }
    char *buffer = new char[size];
    int bytes_read = BIO_read(pBio, buffer, size);
    if (bytes_read != size) {
        delete[] buffer;
        return false;
    }
    sStr.clear();
    sStr.append(buffer, bytes_read);
    delete[] buffer;
    return true;
}
