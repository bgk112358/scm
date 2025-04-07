// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "aes_symm.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include "util/error_utils.h"

using namespace cyber;

AesSymm::AesSymm() {
    context_ = nullptr;
}

AesSymm::~AesSymm() {
    EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)context_);
}

std::string AesSymm::GetAlgorithmName() {
    std::string alg = "AES";
    std::string bits;
    std::string mode;
    switch (keybits_) {
        case 128: bits = "128"; break;
        case 256: bits = "256"; break;
        default:
            return "";
    }
    switch (mode_) {
        case NONE: mode = "NONE"; break;
        case ECB:  mode = "ECB";  break;
        case CBC:  mode = "CBC";  break;
        case CFB:  mode = "CFB";  break;
        case OFB:  mode = "OFB";  break;
        default:
            return "";
    }
    return alg + "-" + bits + "-" + mode;
}

bool AesSymm::Init(ISymm::Mode mode,
                   unsigned char *pucKey, unsigned int uiKeyLen,
                   unsigned char *pucIV, unsigned int uiIVLen,
                   unsigned int uiEncOrDec, bool padding) {
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    std::string algorithm;
    if (pucKey == nullptr) {
        return false;
    }
    if (mode == CBC && uiIVLen != AES_BLOCK_SIZE) {
        return false;
    }
    if (mode == OFB && uiIVLen != AES_BLOCK_SIZE) {
        return false;
    }
    if (mode == CFB && uiIVLen != AES_BLOCK_SIZE) {
        return false;
    }
    keybits_ = uiKeyLen * 8;
    mode_ = mode;
    algorithm = GetAlgorithmName();
    if (algorithm.empty()) {
        Cyber_error_message(algorithm.c_str());
        return false;
    }
    if (!(cipher = EVP_get_cipherbyname(algorithm.c_str()))) {
        Openssl_error(algorithm.c_str());
        return false;
    }
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        Openssl_error(algorithm.c_str());
        return false;
    }
    if (!EVP_CipherInit(ctx, cipher, pucKey, pucIV, (int)uiEncOrDec)) {
        Openssl_error(algorithm.c_str());
        return false;
    }
    if (padding) {
        EVP_CIPHER_CTX_set_padding(ctx, 1);
    } else {
        EVP_CIPHER_CTX_set_padding(ctx, 0);
    }
    if (context_) {
        EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)context_);
    }
    context_ = ctx;
    return true;
}

bool AesSymm::Update(const std::vector<unsigned char> &vInData,
                     std::vector<unsigned char> &vOutData) {
    unsigned char *ucOutData;
    int iOutDataLen = (int)vInData.size();
    if (!(ucOutData = (unsigned char *)OPENSSL_zalloc(vInData.size() + 16))) {
        return false;
    }
    if (context_ == nullptr) {
        return false;
    }
    if (!EVP_CipherUpdate(
            (EVP_CIPHER_CTX *)context_,
            ucOutData,
            &iOutDataLen,
            vInData.data(),
            (int)vInData.size())) {
        Openssl_error("Cipher update fail.");
        OPENSSL_free(ucOutData);
        return false;
    }
    vOutData.assign(ucOutData, ucOutData + iOutDataLen);
    OPENSSL_free(ucOutData);
    return true;
}

bool AesSymm::Final(std::vector<unsigned char> &vOutData) {
    unsigned char ucOutData[32] = {0};
    int iOutDataLen = 32;
    if (context_ == nullptr) {
        return false;
    }
    vOutData.clear();
    if (!EVP_CipherFinal_ex(
            (EVP_CIPHER_CTX *)context_,
            ucOutData,
            &iOutDataLen)) {
        Openssl_error("Cipher final fail.");
        return false;
    }
    vOutData.assign(ucOutData, ucOutData + iOutDataLen);
    return true;
}

bool AesSymm::Compute(const std::vector<unsigned char> &vInData,
                      std::vector<unsigned char> &vOutData) {
    std::vector<unsigned char> vOutData1;
    std::vector<unsigned char> vOutData2;
    if (!Update(vInData, vOutData1)) {
        return false;
    }
    if (!Final(vOutData2)) {
        return false;
    }
    vOutData.assign(vOutData1.begin(), vOutData1.end());
    vOutData.insert(vOutData.end(), vOutData2.begin(), vOutData2.end());
    return true;
}

