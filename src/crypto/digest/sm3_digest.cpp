// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "sm3_digest.h"
#include <openssl/evp.h>

using namespace cyber;

Sm3Digest::Sm3Digest() {
    context_ = nullptr;
}

Sm3Digest::~Sm3Digest() {
    EVP_MD_CTX_free((EVP_MD_CTX *)context_);
}

std::string Sm3Digest::GetAlgorithmName() {
    return "SM3";
}

int Sm3Digest::GetDigestSize() {
    return 32;
}

bool Sm3Digest::Init() {
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

bool Sm3Digest::Update(const unsigned char *data, unsigned int len) {
    if (context_ == nullptr || data == nullptr) {
        return false;
    }
    int rv = EVP_DigestUpdate((EVP_MD_CTX *)context_, data, len);
    if (rv != 1) {
        return false;
    }
    return true;
}

bool Sm3Digest::Final(unsigned char *out, unsigned int *out_len) {
    if (context_ == nullptr || out == nullptr || out_len == nullptr) {
        return false;
    }
    int rv = EVP_DigestFinal((EVP_MD_CTX *)context_, out, out_len);
    if (rv != 1) {
        return false;
    }
    return true;
}

bool Sm3Digest::Compute(const unsigned char *ucInData, unsigned int uiInDataLen,
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