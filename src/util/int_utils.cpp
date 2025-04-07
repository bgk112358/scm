// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "int_utils.h"

using namespace cyber;

void IntUtils::IntToBytes(int num, unsigned char *bytes) {
    if (bytes == nullptr) {
        return;
    }
    bytes[0] = (num >> 24) & 0xFF;
    bytes[1] = (num >> 16) & 0xFF;
    bytes[2] = (num >> 8) & 0xFF;
    bytes[3] = num & 0xFF;
}

int IntUtils::BytesToInt(const unsigned char *bytes) {
    if (bytes == nullptr) {
        return 0;
    }
    return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
}
