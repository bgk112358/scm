//
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//

#ifndef SCM_HMAC_H
#define SCM_HMAC_H

#include <memory>
#include "hmac/ihmac.h"

namespace cyber {

class HMAC {
public:
    typedef std::shared_ptr<IHmac> ptr;
    static HMAC::ptr CreateHmac(const std::string &sAlgorithm);
};

}


#endif //SCM_HMAC_H
