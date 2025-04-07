// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "zuc_symm.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include "util/error_utils.h"

using namespace cyber;

ZucSymm::ZucSymm() {
    context_ = nullptr;
}

ZucSymm::~ZucSymm() {
    EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)context_);
}

std::string ZucSymm::GetAlgorithmName() {
    return "ZUC";
}

bool ZucSymm::Init(ISymm::Mode mode,
                   unsigned char *pucKey, unsigned int uiKeyLen,
                   unsigned char *pucIV, unsigned int uiIVLen,
                   unsigned int uiEncOrDec, bool padding) {
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    std::string algorithm;
    if (pucKey == nullptr) {
        return false;
    }
    keybits_ = uiKeyLen * 8;
    mode_ = mode;
    cipher = EVP_eea3();
    if (uiIVLen != AES_BLOCK_SIZE) {
        return false;
    }
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        Openssl_error(algorithm.c_str());
        return false;
    }
    if (!EVP_CipherInit(ctx, cipher, pucKey, pucIV, (int)uiEncOrDec)) {
        ERR_print_errors_fp(stdout);
        Openssl_error(algorithm.c_str());
        return false;
    }
    if (context_) {
        EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)context_);
    }
    context_ = ctx;
    return true;
}

bool ZucSymm::Update(const std::vector<unsigned char> &vInData,
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

bool ZucSymm::Final(std::vector<unsigned char> &vOutData) {
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

bool ZucSymm::Compute(const std::vector<unsigned char> &vInData,
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

