// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "engine_utils.h"
#include <openssl/objects.h>

using namespace cyber;

static const unsigned char
        IW_MD5_DIGEST_INFO[18] = {
        0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86,
        0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00,
        0x04, 0x10 };

static const unsigned char
        IW_SHA1_DIGEST_INFO[15] = {
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
        0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };

static const unsigned char
        IW_SHA256_DIGEST_INFO[19] = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20 };

static const unsigned char
        IW_SHA512_DIGEST_INFO[19] = {
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
        0x00, 0x04, 0x40 };

std::vector<unsigned char> RsaUtils::EncodeDigestInfo(
        int nid, const std::vector<unsigned char> &sSrc) {
    std::vector<unsigned char> sDst;
    switch (nid) {
        case NID_md5:
            sDst.assign(IW_MD5_DIGEST_INFO,
                        IW_MD5_DIGEST_INFO + sizeof(IW_MD5_DIGEST_INFO));
            sDst.insert(sDst.end(), sSrc.begin(), sSrc.end());
            break;
        case NID_sha1:
            sDst.assign(IW_SHA1_DIGEST_INFO,
                        IW_SHA1_DIGEST_INFO + sizeof(IW_SHA1_DIGEST_INFO));
            sDst.insert(sDst.end(), sSrc.begin(), sSrc.end());
            break;
        case NID_sha256:
            sDst.assign(IW_SHA256_DIGEST_INFO,
                        IW_SHA256_DIGEST_INFO + sizeof(IW_SHA256_DIGEST_INFO));
            sDst.insert(sDst.end(), sSrc.begin(), sSrc.end());
            break;
        case NID_sha512:
            sDst.assign(IW_SHA512_DIGEST_INFO,
                        IW_SHA512_DIGEST_INFO + sizeof(IW_SHA512_DIGEST_INFO));
            sDst.insert(sDst.end(), sSrc.begin(), sSrc.end());
            break;
        default:
            break;
    }
    return sDst;
}

void ErrorUtils::PutError() {

}

std::string EngineHexUtils::EncodeStr(const unsigned char *sStr, unsigned int iLen) {
    std::string s;
    char buf[3] = {0};
    if (sStr == nullptr || iLen == 0) {
        return "";
    }
    for (unsigned int i = 0; i < iLen; ++i) {
        snprintf(buf, sizeof(buf), "%02x", sStr[i]);
        s.append(buf);
    }
    return s;
}