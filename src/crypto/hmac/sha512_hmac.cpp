// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "sha512_hmac.h"
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include "util/error_utils.h"

using namespace cyber;

Sha512Hmac::~Sha512Hmac() {
    EVP_MD_CTX_free((EVP_MD_CTX *)context_);
}

Sha512Hmac::Sha512Hmac() {
    Openssl_error_clear();
    context_ = nullptr;
}

std::string Sha512Hmac::GetAlgorithmName() {
    return "SHA512-HMAC";
}

int Sha512Hmac::GetHmacSize() {
    return SHA512_DIGEST_LENGTH;
}

bool Sha512Hmac::Init(const unsigned char *key, unsigned int key_len) {
    EVP_MD_CTX *digest_context = EVP_MD_CTX_new();
    if (digest_context == nullptr) {
        Openssl_error("Sha512Hmac init ctx fail.");
        return false;
    }
    EVP_PKEY *pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr,
                                          key, (int)key_len);
    if (pkey == nullptr) {
        Openssl_error("Sha512Hmac init mac key fail.");
        return false;
    }
    int rv = EVP_DigestSignInit(digest_context, nullptr, EVP_sha512(), nullptr, pkey);
    if (rv != 1) {
        EVP_PKEY_free(pkey);
        Openssl_error("Sha512Hmac init fail.");
        return false;
    }
    EVP_PKEY_free(pkey);
    context_ = digest_context;
    return true;
}

bool Sha512Hmac::Update(const unsigned char *data, unsigned int len) {
    if (context_ == nullptr || data == nullptr) {
        Cyber_error(error::Code::IndataErr);
        return false;
    }
    int rv = EVP_DigestSignUpdate((EVP_MD_CTX *)context_, data, len);
    if (rv != 1) {
        Openssl_error("Sha512Hmac Update fail.");
        return false;
    }
    return true;
}

bool Sha512Hmac::Final(unsigned char *out, unsigned int *out_len) {
    if (context_ == nullptr || out == nullptr || out_len == nullptr) {
        Cyber_error(error::Code::IndataErr);
        return false;
    }
    size_t len = *out_len;
    int rv = EVP_DigestSignFinal((EVP_MD_CTX *)context_, out, &len);
    if (rv != 1) {
        Openssl_error("Sha512Hmac Final fail.");
        return false;
    }
    *out_len = len;
    return true;
}
