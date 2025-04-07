// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "md5_digest.h"
#include <openssl/evp.h>
#include <openssl/md5.h>

using namespace cyber;

Md5Digest::Md5Digest() {
    context_ = nullptr;
}

Md5Digest::~Md5Digest() {
    EVP_MD_CTX_free((EVP_MD_CTX *)context_);
}

std::string Md5Digest::GetAlgorithmName() {
    return "MD5";
}

int Md5Digest::GetDigestSize() {
    return MD5_DIGEST_LENGTH;
}

bool Md5Digest::Init() {
    std::string algorithmName = GetAlgorithmName();
    const EVP_MD *message_digest = EVP_get_digestbyname(algorithmName.c_str());
    EVP_MD_CTX *digest_context = EVP_MD_CTX_new();
    if (digest_context == nullptr) {
        return false;
    }
    int rv = EVP_DigestInit(digest_context, message_digest);
    if (rv != 1) {
        return false;
    }
    if (context_ != nullptr) {
        EVP_MD_CTX_free((EVP_MD_CTX *)context_);
    }
    context_ = digest_context;
    return true;
}

bool Md5Digest::Update(const unsigned char *data, unsigned int len) {
    if (context_ == nullptr || data == nullptr) {
        return false;
    }
    int rv = EVP_DigestUpdate((EVP_MD_CTX *)context_, data, len);
    if (rv != 1) {
        return false;
    }
    return true;
}

bool Md5Digest::Final(unsigned char *out, unsigned int *out_len) {
    if (context_ == nullptr || out == nullptr || out_len == nullptr) {
        return false;
    }
    int rv = EVP_DigestFinal((EVP_MD_CTX *)context_, out, out_len);
    if (rv != 1) {
        return false;
    }
    return true;
}

bool Md5Digest::Compute(const unsigned char *ucInData, unsigned int uiInDataLen,
                        unsigned char *ucOutData, unsigned int *uiOutDataLen) {
    if (ucInData == nullptr || ucOutData == nullptr || uiOutDataLen == nullptr) {
        return false;
    }
    std::string algorithmName = GetAlgorithmName();
    const EVP_MD *message_digest = EVP_get_digestbyname(algorithmName.c_str());
    int rv = EVP_Digest(ucInData, uiInDataLen,
                        ucOutData, uiOutDataLen,
                        message_digest, nullptr);
    if (rv != 1) {
        return false;
    }
    return true;
}
