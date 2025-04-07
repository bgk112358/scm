// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#include "null_digest.h"
#include <openssl/evp.h>
#include <openssl/sha.h>

using namespace cyber;

NullDigest::NullDigest() {
    context_ = nullptr;
}

std::string NullDigest::GetAlgorithmName() {
    return "NONE";
}

int NullDigest::GetDigestSize() {
    return 0;
}

bool NullDigest::Init() {
    return true;
}

bool NullDigest::Update(const unsigned char *data, unsigned int len) {
    return true;
}

bool NullDigest::Final(unsigned char *out, unsigned int *out_len) {
    return true;
}

bool NullDigest::Compute(const unsigned char *ucInData, unsigned int uiInDataLen,
                        unsigned char *ucOutData, unsigned int *uiOutDataLen) {
    return true;
}
