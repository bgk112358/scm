// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//

#ifndef SVKD_BUILD_CONTAINER_H
#define SVKD_BUILD_CONTAINER_H

#include <string>
#include <vector>
#include <memory>
#include "util/util.h"

namespace cyber {

typedef struct Struct_Container {
    unsigned int   Version;                 // Container Version
    unsigned int   Type;                    // Container Type
    unsigned char  Name[32];                // Container Name
    unsigned int   NameLen;                 // Container Name Len
    unsigned int   Status;                  // Container Status
    unsigned int   Usage;                   // Container Usage
    unsigned int   ExportFlag;              // Export Flag, 1 can export, 0 can`t export
    unsigned int   AlgIdentify;             // Algorithm Identify
    unsigned char  AuthKeyCipher[32];       // Personal Identification Number Encrypt Random Key
    unsigned char  AuthKeyHash[32];         // Random Key Hash
    unsigned int   CipherLen;               // Cipher Data Len
    unsigned char  Cipher[1];               // Cipher Data Value
} Container_st;

const std::string Global_IV  = "d67fb904fc2a831d";
const std::string Global_PIN = "057E580BCB2CCC6118B931754891C188";

 class Container {
 public:
     typedef enum {
         FILE,
         CERTIFICATE,
         PUBLIC_KEY,
         PRIVATE_KEY,
         SYMM_KEY,
     } StorageType;

     typedef enum {
         NONE,
         RSA = 0x00010000,
         ECC = 0x00080000,
         BRAINPOOL_P256R1 = 0x00080001,
         SM2 = 0x00020100,
         SYMM,
     } Algorithm;

     typedef enum {
         SIGN,
         ENC,
         TLS,
         OTA,
         COMMON,
     } Usage;

     typedef enum {
         AVAILABLE   = 0,
         LOCK        = 1,
         EMPTY       = 2,
     } Status;

     Container();
     ~Container();

     // Container Version
     void SetContainerVersion(unsigned int version) {
         container_->Version = version;
     }

     void SetContainerType(unsigned int uiType) {
         container_->Type = uiType;
     }

     // Container Name
     void SetContainerName(const std::string& sName) {
         int len = (int)sName.size();
         if (sName.size() > sizeof(container_->Name)) {
             len = sizeof(container_->Name);
         }
         memcpy(container_->Name, sName.c_str(), len);
         container_->NameLen = len;
     }
     // Container Status
     void SetContainerStatus(Status status) {
         container_->Status = status;
     }
     // Container Usage
     void SetContainerUsage(Usage usage) {
         container_->Usage = usage;
     }
     // Export Flag
     void SetContainerExportFlag(unsigned int uiExportFlag) {
         container_->ExportFlag = uiExportFlag;
     }
     // Algorithm Identify
     void SetAlgorithmIdentify(Algorithm algorithm) {
         container_->AlgIdentify = algorithm;
     }

     // Class Method
     bool BuildContainer();
     std::vector<unsigned char> GetContainerData();

 private:
     std::string pin_str_;
     std::vector<unsigned char> plaintextData_;
     Container_st *container_ = nullptr;

 public:
     std::string containerPin_ = Global_PIN;
     std::vector<unsigned char> vOrgData;


 };

}

#endif //SVKD_BUILD_CONTAINER_H
