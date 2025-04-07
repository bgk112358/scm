// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_CYBER_SM3_PREPROCESS_H
#define CYBERLIB_BUILD_CYBER_SM3_PREPROCESS_H

int sm3_digest_z(const unsigned char *id,
                 int id_len,
                 const unsigned char *pub_key,
                 unsigned char *z_digest);

int sm3_digest_with_preprocess(const unsigned char *message,
                               int message_len,
                               const unsigned char *id,
                               int id_len,
                               const unsigned char *pub_key,
                               unsigned char *digest);

#endif //CYBERLIB_BUILD_CYBER_SM3_PREPROCESS_H
