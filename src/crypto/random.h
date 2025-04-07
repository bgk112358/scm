// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//
#ifndef SVKD_BUILD_RANDOM_H
#define SVKD_BUILD_RANDOM_H

#include <string>
#include <vector>

namespace cyber {

// Random bits.
// Unix-like system use /dev/urandom
// Windows use CryptGenRandom
void RandBytes(void *bytes, size_t length);

// Fills |bytes| use random bits.
void RandBytes(std::vector<unsigned char>& bytes);

// Return random string.
std::string RandString(size_t length);

// Return random hex string.
std::string RandHexString(size_t length);


}


#endif //SVKD_BUILD_RANDOM_H
