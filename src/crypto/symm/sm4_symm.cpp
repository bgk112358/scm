// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "sm4_symm.h"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include "util/error_utils.h"

using namespace cyber;

Sm4Symm::Sm4Symm() {
    Openssl_error_clear();
    context_ = nullptr;
}

Sm4Symm::~Sm4Symm() {
    EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)context_);
}

std::string Sm4Symm::GetAlgorithmName() {
    std::string alg = "SM4";
    std::string bits;
    std::string mode;
    switch (mode_) {
        case NONE: mode = "NONE"; break;
        case ECB:  mode = "ECB";  break;
        case CBC:  mode = "CBC";  break;
        case CFB:  mode = "CFB";  break;
        case OFB:  mode = "OFB";  break;
        default:
            return "";
    }
    return alg + "-" + mode;
}

bool Sm4Symm::Init(ISymm::Mode mode,
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
    keybits_ = uiKeyLen;
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
    context_ = ctx;
    return true;
}

bool Sm4Symm::Update(const std::vector<unsigned char> &sInData,
                     std::vector<unsigned char> &sOutData) {
    unsigned char *ucOutData;
    int iOutDataLen = (int)sInData.size();
    if (!(ucOutData = (unsigned char *)OPENSSL_zalloc(sInData.size() + 16))) {
        Openssl_error("zalloc");
        return false;
    }
    if (context_ == nullptr) {
        return false;
    }
    if (!EVP_CipherUpdate(
            (EVP_CIPHER_CTX *)context_,
            ucOutData,
            &iOutDataLen,
            sInData.data(),
            (int)sInData.size())) {
        Openssl_error("Cipher update fail.");
        OPENSSL_free(ucOutData);
        return false;
    }
    sOutData.clear();
    sOutData.assign(ucOutData, ucOutData + iOutDataLen);
    OPENSSL_free(ucOutData);
    return true;
}

bool Sm4Symm::Final(std::vector<unsigned char> &sOutData) {
    unsigned char ucOutData[32] = {0};
    int iOutDataLen = 32;
    if (context_ == nullptr) {
        return false;
    }
    if (!EVP_CipherFinal_ex(
            (EVP_CIPHER_CTX *)context_,
            ucOutData,
            &iOutDataLen)) {
        Openssl_error("Cipher final fail.");
        return false;
    }
    sOutData.assign(ucOutData, ucOutData + iOutDataLen);
    return true;
}


bool Sm4Symm::Compute(const std::vector<unsigned char> &vInData,
                      std::vector<unsigned char> &vOutData) {
    std::vector<unsigned char> vOutData1;
    std::vector<unsigned char> vOutData2;
    vOutData.clear();
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