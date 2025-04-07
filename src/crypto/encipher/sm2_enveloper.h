// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_SM2_ENVELOPER_H
#define CYBERLIB_BUILD_SM2_ENVELOPER_H

#include "../generators/ikeypair.h"

namespace cyber {

class Sm2Enveloper {
public:
    static bool DecryptEnveloped(IKeyPair *iKeyPair,
                                 const std::vector<uint8_t> &vEnvelopedData,
                                 std::vector<uint8_t> &vPlainData);
};


}






#endif //CYBERLIB_BUILD_SM2_ENVELOPER_H
