// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "sha1_hmac.h"
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include "util/error_utils.h"

using namespace cyber;

Sha1Hmac::~Sha1Hmac() {
    EVP_MD_CTX_free((EVP_MD_CTX *)context_);
}

Sha1Hmac::Sha1Hmac() {
    Openssl_error_clear();
    context_ = nullptr;
}

std::string Sha1Hmac::GetAlgorithmName() {
    return "SHA1-HMAC";
}

int Sha1Hmac::GetHmacSize() {
    return SHA_DIGEST_LENGTH;
}

bool Sha1Hmac::Init(const unsigned char *key, unsigned int key_len) {
    EVP_MD_CTX *digest_context = EVP_MD_CTX_new();
    if (digest_context == nullptr) {
        Openssl_error("Sha1Hmac init ctx fail.");
        return false;
    }
    EVP_PKEY *pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr,
                                          key, (int)key_len);
    if (pkey == nullptr) {
        Openssl_error("Sha1Hmac init mac key fail.");
        return false;
    }
    int rv = EVP_DigestSignInit(digest_context, nullptr, EVP_sha1(), nullptr, pkey);
    if (rv != 1) {
        EVP_PKEY_free(pkey);
        Openssl_error("Sha1Hmac init fail.");
        return false;
    }
    EVP_PKEY_free(pkey);
    context_ = digest_context;
    return true;
}

bool Sha1Hmac::Update(const unsigned char *data, unsigned int len) {
    if (context_ == nullptr || data == nullptr) {
        Cyber_error(error::Code::IndataErr);
        return false;
    }
    int rv = EVP_DigestSignUpdate((EVP_MD_CTX *)context_, data, len);
    if (rv != 1) {
        Openssl_error("Sha1Hmac Update fail.");
        return false;
    }
    return true;
}

bool Sha1Hmac::Final(unsigned char *out, unsigned int *out_len) {
    if (context_ == nullptr || out == nullptr || out_len == nullptr) {
        Cyber_error(error::Code::IndataErr);
        return false;
    }
    size_t len = *out_len;
    int rv = EVP_DigestSignFinal((EVP_MD_CTX *)context_, out, &len);
    if (rv != 1) {
        Openssl_error("Sha1Hmac SignFinal");
        return false;
    }
    *out_len = len;
    return true;
}