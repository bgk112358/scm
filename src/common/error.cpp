// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//

#include "error.h"

namespace cyber {

 // This is the default Logger object.
 Errors errors = []() -> Errors {
     Errors defaultErrors;
     return defaultErrors;
 }();

}
