// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "sm3_hmac.h"
#include <openssl/hmac.h>
#include "../digest/sm3_digest.h"
#include "util/error_utils.h"

using namespace cyber;

Sm3Hmac::~Sm3Hmac() {
    EVP_MD_CTX_free((EVP_MD_CTX *)context_);
}

Sm3Hmac::Sm3Hmac() {
    Openssl_error_clear();
    context_ = nullptr;
}

std::string Sm3Hmac::GetAlgorithmName() {
    return "SM3-HMAC";
}

int Sm3Hmac::GetHmacSize() {
    return SM3_DIGEST_LENGTH;
}

bool Sm3Hmac::Init(const unsigned char *key, unsigned int key_len) {
    EVP_MD_CTX *digest_context = EVP_MD_CTX_new();
    if (digest_context == nullptr) {
        Openssl_error("Sm3Hmac init ctx fail.");
        return false;
    }
    EVP_PKEY *pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr,
                                          key, (int)key_len);
    if (pkey == nullptr) {
        Openssl_error("Sm3Hmac init mac key fail.");
        return false;
    }
    int rv = EVP_DigestSignInit(digest_context, nullptr, EVP_sm3(), nullptr, pkey);
    if (rv != 1) {
        EVP_PKEY_free(pkey);
        Openssl_error("Sm3Hmac init fail.");
        return false;
    }
    EVP_PKEY_free(pkey);
    context_ = digest_context;
    return true;
}

bool Sm3Hmac::Update(const unsigned char *data, unsigned int len) {
    if (context_ == nullptr || data == nullptr) {
        Cyber_error(error::Code::IndataErr);
        return false;
    }
    int rv = EVP_DigestSignUpdate((EVP_MD_CTX *)context_, data, len);
    if (rv != 1) {
        Openssl_error("Sm3Hmac Update fail.");
        return false;
    }
    return true;
}

bool Sm3Hmac::Final(unsigned char *out, unsigned int *out_len) {
    if (context_ == nullptr || out == nullptr || out_len == nullptr) {
        Cyber_error(error::Code::IndataErr);
        return false;
    }
    size_t len = *out_len;
    int rv = EVP_DigestSignFinal((EVP_MD_CTX *)context_, out, &len);
    if (rv != 1) {
        Openssl_error("Sm3Hmac Final fail.");
        return false;
    }
    *out_len = len;
    return true;
}
