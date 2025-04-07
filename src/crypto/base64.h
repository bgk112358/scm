// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//
#ifndef SVKD_BUILD_BASE64_H
#define SVKD_BUILD_BASE64_H

#include <string>
#include <vector>

namespace cyber {

/**
 * @brief base64 encoding
 * @param from data to be encoded
 * @return coded data
 */
std::string Base64Encode(const std::string &from);

/**
 * @brief base64 encoding
 * @param from data to be encoded
 * @param len  data len
 * @return coded data
 */
std::string Base64Encode(const unsigned char *from, unsigned int len);

/**
 * @brief base64 decoding
 * @param from coded data
 * @return decoded data
 */
std::vector<unsigned char> Base64Decode(const std::string &from);

/**
 * @brief base64 decoding
 * @param from coded data
 * @param len  coded data len
 * @return decoded data
 */
std::vector<unsigned char> Base64Decode(const unsigned char *from, unsigned int len);

}

#endif //SVKD_BUILD_BASE64_H
