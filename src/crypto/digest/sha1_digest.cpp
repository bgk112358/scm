// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "sha1_digest.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "util/openssl_utils.h"
#include "util/error_utils.h"

using namespace cyber;

Sha1Digest::Sha1Digest() {
    context_ = nullptr;
}

Sha1Digest::~Sha1Digest() {
    EVP_MD_CTX_free((EVP_MD_CTX *)context_);
}

std::string Sha1Digest::GetAlgorithmName() {
    return "SHA1";
}

int Sha1Digest::GetDigestSize() {
    return SHA_DIGEST_LENGTH;
}

bool Sha1Digest::Init() {
    std::string algorithmName = GetAlgorithmName();
    const EVP_MD *message_digest = EVP_get_digestbyname(algorithmName.c_str());
    EVP_MD_CTX *digest_context = EVP_MD_CTX_new();
    if (digest_context == nullptr) {
        Openssl_error("Sha1 init ctx fail.");
        return false;
    }
    int rv = EVP_DigestInit(digest_context, message_digest);
    if (rv != 1) {
        Openssl_error("Sha1 init fail.");
        return false;
    }
    context_ = digest_context;
    return true;
}

bool Sha1Digest::Update(const unsigned char *data, unsigned int len) {
    if (context_ == nullptr || data == nullptr) {
        Cyber_error(error::Code::IndataErr);
        return false;
    }
    int rv = EVP_DigestUpdate((EVP_MD_CTX *)context_, data, len);
    if (rv != 1) {
        Openssl_error("Sha1 Update fail.");
        return false;
    }
    return true;
}

bool Sha1Digest::Final(unsigned char *out, unsigned int *out_len) {
    if (context_ == nullptr || out == nullptr || out_len == nullptr) {
        Cyber_error(error::Code::IndataErr);
        return false;
    }
    int rv = EVP_DigestFinal((EVP_MD_CTX *)context_, out, out_len);
    if (rv != 1) {
        Openssl_error("Sha1 Final fail.");
        return false;
    }
    return true;
}

bool Sha1Digest::Compute(const unsigned char *ucInData, unsigned int uiInDataLen,
                         unsigned char *ucOutData, unsigned int *uiOutDataLen) {
    if (ucInData == nullptr || ucOutData == nullptr || uiOutDataLen == nullptr) {
        Cyber_error(error::Code::IndataErr);
        return false;
    }
    std::string algorithmName = GetAlgorithmName();
    const EVP_MD *message_digest = EVP_get_digestbyname(algorithmName.c_str());
    int rv = EVP_Digest(ucInData, uiInDataLen,
                        ucOutData, uiOutDataLen,
                        message_digest, nullptr);
    if (rv != 1) {
        Openssl_error("Sha1 Digest fail.");
        return false;
    }
    return true;
}

