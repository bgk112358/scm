// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "container_resolver.h"
#include "crypto/crypto.h"

using namespace cyber;

ContainerResolver::ContainerResolver(
        const std::vector<unsigned char> &vInData) {
    vInData_ = vInData;
}

ContainerResolver::~ContainerResolver() = default;

int ContainerResolver::Resolver(const std::vector<unsigned char> &vPinData) {
    int rv = error::Code::Ok;
    IDigest *digest = nullptr;
    Symmetric::ptr iSymmetric = nullptr;
    unsigned char ucHash[32] = {0};
    unsigned int uiHashLen = 32;
    std::vector<unsigned char> vData;
    std::vector<unsigned char> vOutData;
    Container_st *container = nullptr;
    if (vInData_.size() < sizeof(Container_st)) {
        rv = error::Code::IndataLenErr;
        goto cleanup;
    }
    // Container
    container = (Container_st *)OPENSSL_zalloc(vInData_.size());
    if (container == nullptr) {
        rv = error::Code::MemoryErr;
        goto cleanup;
    }
    memcpy(container, vInData_.data(), vInData_.size());
    // Pin hash
    digest = Digest::CreateDigest("SHA256");
    if (digest == nullptr) {
        rv = error::Code::AlgoTypeErr;
        goto cleanup;
    }
    if (vPinData.empty()) {
        digest->Compute((unsigned char *)Global_PIN.c_str(), Global_PIN.length(),
                        ucHash, &uiHashLen);
    } else {
        digest->Compute(vPinData.data(), vPinData.size(),
                        ucHash, &uiHashLen);
    }
    // Decrypt random key
    iSymmetric = Symmetric::CreateSymmPtr("AES");
    if (iSymmetric == nullptr) {
        rv = error::Code::AlgoTypeErr;
        goto cleanup;
    }
    vData.assign(container->AuthKeyCipher,
                 container->AuthKeyCipher + sizeof(container->AuthKeyCipher));
    if(!iSymmetric->Init(ISymm::CBC, ucHash, uiHashLen,
                        (unsigned char *)Global_IV.c_str(), Global_IV.size(),
                        0, false) ||
       !iSymmetric->Compute(vData, vOutData)) {
        rv = error::Code::DecErr;
        goto cleanup;
    }
    if (!digest->Compute(vOutData.data(), vOutData.size(), ucHash, &uiHashLen)) {
        rv = error::Code::HashErr;
        goto cleanup;
    }
    if (memcmp(ucHash, container->AuthKeyHash, uiHashLen) != 0) {
        rv = error::Code::HashNotEqualErr;
        goto cleanup;
    }
    vData.assign(container->Cipher, container->Cipher + container->CipherLen);
    if(!iSymmetric->Init(ISymm::CBC, vOutData.data(), vOutData.size(),
                        (unsigned char *)Global_IV.c_str(), Global_IV.size(),
                        0, true) ||
       !iSymmetric->Compute(vData, vOutData)) {
        rv = error::Code::DecErr;
        goto cleanup;
    }
    vPlainData_.assign(vOutData.begin(), vOutData.end());
    uiVersion_     = container->Version;
    uiType_        = container->Type;
    sName_.assign((const char *)container->Name, container->NameLen);
    uiStatus_      = container->Status;
    uiUsage_       = container->Usage;
    uiExportFlag_  = container->ExportFlag;
    uiAlgIdentify_ = container->AlgIdentify;
cleanup:
    delete digest;
    OPENSSL_free(container);
    return rv;
}

std::vector<unsigned char> ContainerResolver::GetPlainData() {
    return vPlainData_;
}

unsigned int ContainerResolver::GetVersion() const {
    return uiVersion_;
}

unsigned int ContainerResolver::GetType() const {
    return uiType_;
}

std::string ContainerResolver::GetName() const {
    return sName_;
}

unsigned int ContainerResolver::GetStatus() const {
    return uiStatus_;
}

unsigned int ContainerResolver::GetUsage() const {
    return uiUsage_;
}

unsigned int ContainerResolver::GetExportFlag() const {
    return uiExportFlag_;
}

unsigned int ContainerResolver::GetAlgIdentify() const {
    return uiAlgIdentify_;
}

std::string ContainerResolver::ToString() const {
    std::string result("Container: ");
    result.append("\n");
    result.append(" - Version:");
    result.append(std::to_string(uiVersion_));
    result.append("\n");
    result.append(" - Type:");
    result.append(std::to_string(uiType_));
    result.append("\n");
    result.append(" - Name:");
    result.append(sName_);
    result.append("\n");
    result.append(" - Status:");
    result.append(std::to_string(uiStatus_));
    result.append("\n");
    result.append(" - Usage:");
    result.append(std::to_string(uiUsage_));
    result.append("\n");
    result.append(" - ExportFlag:");
    result.append(std::to_string(uiExportFlag_));
    result.append("\n");
    result.append(" - AlgIdentify:");
    result.append(std::to_string(uiAlgIdentify_));
    result.append("\n");
    return result;
}
