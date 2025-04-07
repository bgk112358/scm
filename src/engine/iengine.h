// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef CYBERLIB_BUILD_IDRIVER_H
#define CYBERLIB_BUILD_IDRIVER_H

namespace cyber {
#define RSA_MAX_BITS  2048
#define RSA_MAX_LEN   ((RSA_MAX_BITS + 7) / 8)

typedef struct RsaPublicKey_st {
    unsigned int  bits;
    unsigned char m[RSA_MAX_LEN];
    unsigned char e[RSA_MAX_LEN];
} RSAPUBLICKEY, *PRSAPUBLICKEY;

#define ECC_MAX_BITS  512
#define ECC_MAX_LEN   ((ECC_MAX_BITS + 7) / 8)

typedef struct EccPublicKey_st {
    unsigned int  bits;
    unsigned char x[ECC_MAX_LEN];
    unsigned char y[ECC_MAX_LEN];
} ECCPUBLICKEY, *PECCPUBLICKEY;

class IEngine {
public:
    virtual ~IEngine() = default;
    // Devices operation interface
    virtual int Initialize() = 0;

    virtual int Finalize() = 0;

    virtual int Login(unsigned int uiUsrType,
                      unsigned char *pucContainerName,
                      unsigned int uiContainerNameLen,
                      unsigned char *pucPin,
                      unsigned int uiPinLen,
                      unsigned int *puiRemainCount) = 0;

    virtual int Logout(unsigned int uiUsrType) = 0;

    // Cryptographic operation interface
    virtual int GenerateRsaKeyPair(unsigned char *pucKeyID,
                                   unsigned int uiKeyBits,
                                   PRSAPUBLICKEY pstRSAPublicKey) = 0;

    virtual int GetRsaPublicKey(unsigned char *pucKeyID,
                                PRSAPUBLICKEY pstRSAPublicKey) = 0;

    virtual int RsaPublicKeyCalc(RSAPUBLICKEY stRSAPublicKey,
                                 unsigned char *pucDataIn,
                                 unsigned int uiDataInLen,
                                 unsigned char *pucDataOut,
                                 unsigned int  *puiDataOutLen) = 0;

    virtual int RsaPrivateKeyCalc(unsigned char *pucKeyID,
                                  unsigned char *pucDataIn,
                                  unsigned int uiDataInLen,
                                  unsigned char *pucDataOut,
                                  unsigned int *puiDataOutLen) = 0;

    // Generate Ecc KeyPair
    virtual int GenerateEccKeyPair(unsigned char *pucKeyID,
                                   unsigned int uiCurveType,
                                   PECCPUBLICKEY pstEccPublicKey) = 0;

    // Get Ecc PublicKey
    virtual int GetEccPublicKey(unsigned char *pucKeyID,
                                PECCPUBLICKEY pstEccPublicKey) = 0;

    // Ecc Sign
    virtual int EccSign(unsigned char *pucKeyID,
                        unsigned char *pucDgstIn,
                        unsigned int uiDgstInLen,
                        unsigned char *pucDataOut,
                        unsigned int  *puiDataOutLen) = 0;

    // Ecc Verify Sign
    virtual int EccVerifySign(ECCPUBLICKEY stEccPublicKey,
                              unsigned char *pucDgstIn,
                              unsigned int uiDgstInLen,
                              unsigned char *pucSignData,
                              unsigned int puiSignDataLen) = 0;

    // Ecc Sign
    virtual int EccDecrypt(unsigned char *pucKeyID,
                           unsigned char *pucDataIn,
                           unsigned int uiDataInLen,
                           unsigned char *pucDataOut,
                           unsigned int  *puiDataOutLen) = 0;


};



}

#endif //CYBERLIB_BUILD_IDRIVER_H
