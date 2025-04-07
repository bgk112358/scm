// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//

#include "container.h"
#include <openssl/bio.h>
#include "crypto/crypto.h"
#include "util/util.h"

using namespace cyber;

Container::Container() {
    if (container_ == nullptr) {
        container_ = (Container_st *)OPENSSL_zalloc(sizeof(Container_st));
    }
}

Container::~Container() {
    OPENSSL_free(container_);
    container_ = nullptr;
}

bool Container::BuildContainer() {
    int rv = false;
    IDigest *iDigest = nullptr;
    ISymm *iSymmetric = nullptr;
    unsigned char ucHash[32] = {0};
    unsigned int  uiHashLen = 32;
    unsigned char ucRandom[32] = {0};
    unsigned int  uiRandomLen = 32;
    std::vector<unsigned char> vInData, vOutData, vRandomBytes;
    size_t len = sizeof(Container_st) + vOrgData.size() + 16;
    auto *container = (Container_st *)OPENSSL_zalloc(len);
    if (container == nullptr) {
        goto cleanup;
    }
    memcpy(container, container_, sizeof(Container_st));
    OPENSSL_free(container_);
    container_ = container;
    iDigest = Digest::CreateDigest("SHA256");
    if (iDigest == nullptr) {
        goto cleanup;
    }
    // Container AuthKey
    RandBytes(ucRandom, uiRandomLen);
    if (!iDigest->Compute(ucRandom, uiRandomLen, ucHash, &uiHashLen)) {
        goto cleanup;
    }
    memcpy(container_->AuthKeyHash, ucHash, uiHashLen);
    uiHashLen = 32;
    if (!iDigest->Compute((const unsigned char *)containerPin_.c_str(),
                         containerPin_.size(),
                         ucHash, &uiHashLen)) {
        goto cleanup;
    }
    iSymmetric = Symmetric::CreateSymm("AES");
    if (!iSymmetric) {
        goto cleanup;
    }
    vInData.assign(ucRandom, ucRandom + uiRandomLen);
    if (!iSymmetric->Init(ISymm::CBC, ucHash, uiHashLen,
                         (unsigned char *)Global_IV.c_str(), Global_IV.length(),
                         1, false) ||
        !iSymmetric->Compute(vInData, vOutData)) {
        goto cleanup;
    }
    memcpy(container_->AuthKeyCipher, vOutData.data(), sizeof(container_->AuthKeyCipher));
    // Container Cipher
    if (!iSymmetric->Init(ISymm::CBC, ucRandom, uiRandomLen,
                         (unsigned char *)Global_IV.c_str(), Global_IV.length(),
                         1, true) ||
        !iSymmetric->Compute(vOrgData, vOutData)) {
        goto cleanup;
    }
    container_->CipherLen = vOutData.size();
    memcpy(container_->Cipher, vOutData.data(), vOutData.size());
    rv = true;
cleanup:
    delete iDigest;
    delete iSymmetric;
    return rv;
}

std::vector<unsigned char> Container::GetContainerData() {
    std::vector<unsigned char> vData;
    size_t total_len = sizeof(Container_st) + container_->CipherLen;
    vData.assign((unsigned char *)container_,
                 (unsigned char *)container_ + total_len);
    return vData;
}


