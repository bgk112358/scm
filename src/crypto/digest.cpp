// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "digest.h"
#include "digest/null_digest.h"
#include "digest/md5_digest.h"
#include "digest/sha1_digest.h"
#include "digest/sha256_digest.h"
#include "digest/sha512_digest.h"
#include "digest/sm3_digest.h"
#include "util/string_utils.h"

using namespace cyber;

IDigest *Digest::CreateDigest(const std::string &sAlgorithm) {
    IDigest *digest;
    if (StringUtils::StartWith(sAlgorithm, "MD5"))
    {
        digest = new Md5Digest();
    }
    else if (StringUtils::StartWith(sAlgorithm, "SM3"))
    {
        digest = new Sm3Digest();
    }
    else if (StringUtils::StartWith(sAlgorithm, "SHA1"))
    {
        digest = new Sha1Digest();
    }
    else if (StringUtils::StartWith(sAlgorithm, "SHA256"))
    {
        digest = new Sha256Digest();
    }
    else if (StringUtils::StartWith(sAlgorithm, "SHA512"))
    {
        digest = new Sha512Digest();
    }
    else
    {
        digest = new NullDigest();
    }
    return digest;
}