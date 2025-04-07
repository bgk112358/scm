// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_CATARC_ENGINE_H
#define CYBERLIB_BUILD_CATARC_ENGINE_H

#include "../iengine.h"

namespace cyber {

class CatarcEngine : public IEngine {
public:

    // Devices operation interface
    int Initialize() override;

    int Finalize() override;

    int Login(unsigned int uiUsrType,
              unsigned char *pucContainerName,
              unsigned int uiContainerNameLen,
              unsigned char *pucPin,
              unsigned int uiPinLen,
              unsigned int *puiRemainCount) override;

    int Logout(unsigned int uiUsrType) override;

    // Cryptographic operation interface
    int GenerateRsaKeyPair(unsigned char *pucKeyID,
                           unsigned int uiKeyBits,
                           PRSAPUBLICKEY pstRSAPublicKey) override;

    int GetRsaPublicKey(unsigned char *pucKeyID,
                        PRSAPUBLICKEY pstRSAPublicKey) override;

    int RsaPublicKeyCalc(RSAPUBLICKEY stRSAPublicKey,
                         unsigned char *pucDataIn,
                         unsigned int uiDataInLen,
                         unsigned char *pucDataOut,
                         unsigned int  *puiDataOutLen) override;

    int RsaPrivateKeyCalc(unsigned char *pucKeyID,
                          unsigned char *pucDataIn,
                          unsigned int uiDataInLen,
                          unsigned char *pucDataOut,
                          unsigned int *puiDataOutLen) override;

    // Generate Ecc KeyPair
    int GenerateEccKeyPair(unsigned char *pucKeyID,
                           unsigned int uiCurveType,
                           PECCPUBLICKEY pstEccPublicKey) override;

    // Get Ecc PublicKey
    int GetEccPublicKey(unsigned char *pucKeyID,
                        PECCPUBLICKEY pstEccPublicKey) override;

    // Ecc Sign
    int EccSign(unsigned char *pucKeyID,
                unsigned char *pucDgstIn,
                unsigned int uiDgstInLen,
                unsigned char *pucDataOut,
                unsigned int *puiDataOutLen) override;

    // Ecc Verify Sign
    int EccVerifySign(ECCPUBLICKEY stEccPublicKey,
                      unsigned char *pucDgstIn,
                      unsigned int uiDgstInLen,
                      unsigned char *pucSignData,
                      unsigned int puiSignDataLen) override;

    // Ecc Decrypt(Only support sm2)
    int EccDecrypt(unsigned char *pucKeyID,
                   unsigned char *pucDataIn,
                   unsigned int uiDataInLen,
                   unsigned char *pucDataOut,
                   unsigned int *puiDataOutLen) override;


};

}

#endif //CYBERLIB_BUILD_CATARC_ENGINE_H
