// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "path_utils.h"
#include "hex_utils.h"
#include "crypto/digest/md5_digest.h"
#include "memory"

using namespace cyber;
std::string PathUtils::JoinPath(const std::string &sDir,
                                const std::string &sFile) {
    std::string s(sDir);
    if (sDir.empty())
    {
        return s;
    }
    if (sDir.back() != '/' && sDir.back() != '\\') {
#ifdef __WIN32
        s.append("\\");
#else
        s.append("/");
#endif
    }
    s.append(sFile);
    return s;
}

std::string ExtToString(Ext ext) {
    switch (ext) {
        case CERT_CHAIN:    return "certificate_chain.crt";
        case SIGN_CERT:     return ".sign.crt";
        case SIGN_PUB_KEY:  return ".sign.pub.key";
        case SIGN_KEY:      return ".sign.key";
        case ENC_CERT:      return ".enc.crt";
        case ENC_PUB_KEY:   return ".enc.pub.key";
        case ENC_KEY:       return ".enc.key";
        case CRL:           return ".crl";
        case CSR:           return ".csr";
        case UUID:          return ".uuid";
        default:            return "";
    }
}

std::string PathUtils::HashPath(const std::string &sDir,
                                const std::string &sIdentify,
                                int ext) {
    std::string s;
    unsigned char ucDigest[16] = {0};
    unsigned int uiDigestLen   = 0;
    std::unique_ptr<Md5Digest> md5Digest(new Md5Digest);
    if (md5Digest == nullptr) {
        return "";
    }
    uiDigestLen   = md5Digest->GetDigestSize();
    if (!md5Digest->Compute((unsigned char *)sIdentify.data(), sIdentify.length(),
                            ucDigest, &uiDigestLen)) {
        memset(ucDigest, 0x11, sizeof(ucDigest));
    }
    s = JoinPath(sDir, HexUtils::EncodeStr(ucDigest, uiDigestLen));
    Ext extension = static_cast<Ext>(ext);
    std::string sExt = ExtToString(extension);
    if (extension == Ext::CERT_CHAIN) {
        s.clear();
        s = JoinPath(sDir, sExt);
    } else {
        s.append(sExt);
    }
    return s;
}
