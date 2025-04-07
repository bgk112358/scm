// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "id_utils.h"
#include "time_utils.h"
#include "hex_utils.h"
#include "../crypto/random.h"
#include "../crypto/digest/md5_digest.h"

using namespace cyber;

std::string UUIDUtils::Generate() {
    Md5Digest md5Digest;
    unsigned char digest[16] = {0};
    unsigned int  digest_len = 16;
    std::string timestamp = TimeUtils::UnixTimeStamp();
    std::string random    = RandHexString(16);
    std::string buffer    = timestamp + random;
    if (!md5Digest.Compute((unsigned char *)buffer.data(), buffer.length(),
                           digest, &digest_len)) {
        return "";
    }
    return HexUtils::EncodeStr(digest, digest_len);
}
