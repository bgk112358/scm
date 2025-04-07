// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "sm2_enveloper.h"
#include <vector>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include "../asymmetric_encipher.h"
#include "util/error_utils.h"

using namespace cyber;

typedef char	     	    INT8;
typedef signed short		INT16;
typedef signed int		    INT32;
typedef unsigned char		UINT8;
typedef unsigned short		UINT16;
typedef unsigned int		UINT32;
typedef long			    BOOL;
typedef UINT8			    BYTE;

# ifndef SGD_NATIVE_LONG
typedef INT32			    LONG;
typedef UINT32			    ULONG;
# else
typedef long			    LONG;
typedef unsigned long		ULONG;
# endif

#define ECC_MAX_XCOORDINATE_BITS_LEN	512
#define ECC_MAX_YCOORDINATE_BITS_LEN	512
#pragma pack(1)
typedef struct Struct_ECCPUBLICKEYBLOB {
    ULONG	BitLen;
    BYTE	XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
    BYTE	YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN/8];
} ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;

typedef struct Struct_ECCCIPHERBLOB{
    BYTE	XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
    BYTE	YCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
    BYTE	HASH[32];
    UINT32	CipherLen;
    BYTE	Cipher[1];
} ECCCIPHERBLOB, *PECCCIPHERBLOB;

typedef struct SKF_ENVELOPEDKEYBLOB {
    ULONG	Version;
    ULONG	ulSymmAlgID;
    ULONG	ulBits;
    BYTE	cbEncryptedPriKey[64];
    ECCPUBLICKEYBLOB	PubKey;
    ECCCIPHERBLOB		ECCCipherBlob;
} ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;
#pragma pack()

typedef struct SM2_Ciphertext_st SM2_Ciphertext_ex;
DECLARE_ASN1_FUNCTIONS(SM2_Ciphertext_ex)
struct SM2_Ciphertext_st {
    BIGNUM *C1x;
    BIGNUM *C1y;
    ASN1_OCTET_STRING *C3;
    ASN1_OCTET_STRING *C2;
};

ASN1_SEQUENCE(SM2_Ciphertext_ex) = {
        ASN1_SIMPLE(SM2_Ciphertext_ex, C1x, BIGNUM),
        ASN1_SIMPLE(SM2_Ciphertext_ex, C1y, BIGNUM),
        ASN1_SIMPLE(SM2_Ciphertext_ex, C3, ASN1_OCTET_STRING),
        ASN1_SIMPLE(SM2_Ciphertext_ex, C2, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(SM2_Ciphertext_ex)

IMPLEMENT_ASN1_FUNCTIONS(SM2_Ciphertext_ex)

// Decrypt Enveloped
bool Sm2Enveloper::DecryptEnveloped(IKeyPair *iKeyPair,
                                    const std::vector<uint8_t> &vEnvelopedData,
                                    std::vector<uint8_t> &vPlainData) {
    bool res = false;
    unsigned char *pucBuffer = nullptr;
    unsigned char ucPrivateKey[32] = {0};
    int iBufferLen;
    std::vector<unsigned char> vCipherData, vBuffer;
    AsymmetricEncipher::ptr iEncipher = nullptr;
    BIGNUM *c1 = nullptr, *c2 = nullptr;
    ERR_clear_error();
    EVP_CIPHER_CTX *cipherCtx = nullptr;
    ENVELOPEDKEYBLOB *pEnvelopedKeyBlob;
    struct SM2_Ciphertext_st ciphertext_st = { nullptr };
    Openssl_error_clear();
    if (vEnvelopedData.size() < sizeof(ENVELOPEDKEYBLOB))
    {
        Cyber_error_message("Input size too small.");
        goto cleanup;
    }
    pEnvelopedKeyBlob = (ENVELOPEDKEYBLOB *)vEnvelopedData.data();
    if (!(c1 = BN_bin2bn(pEnvelopedKeyBlob->ECCCipherBlob.XCoordinate + 32,
                         32, nullptr)) ||
        !(c2 = BN_bin2bn(pEnvelopedKeyBlob->ECCCipherBlob.YCoordinate + 32,
                         32, nullptr))) {
        Openssl_error("BN_bin2bn fail.");
        goto cleanup;
    }
    ciphertext_st.C1x = c1;
    ciphertext_st.C1y = c2;
    if (!(ciphertext_st.C3 = ASN1_OCTET_STRING_new()) ||
        !(ciphertext_st.C2 = ASN1_OCTET_STRING_new())) {
        Openssl_error("ASN1_OCTET_STRING_new fail.");
        goto cleanup;
    }
    if (!ASN1_OCTET_STRING_set(ciphertext_st.C3, pEnvelopedKeyBlob->ECCCipherBlob.HASH,
                               sizeof(pEnvelopedKeyBlob->ECCCipherBlob.HASH)) ||
        !ASN1_OCTET_STRING_set(ciphertext_st.C2, pEnvelopedKeyBlob->ECCCipherBlob.Cipher,
                               (int)pEnvelopedKeyBlob->ECCCipherBlob.CipherLen)) {
        Openssl_error("ASN1_OCTET_STRING_set fail.");
        goto cleanup;
    }
    iBufferLen = i2d_SM2_Ciphertext_ex(&ciphertext_st, &pucBuffer);
    if (iBufferLen <= 0) {
        Openssl_error("i2d_SM2_Ciphertext_ex fail.");
        goto cleanup;
    }
    vCipherData.assign(pucBuffer, pucBuffer + iBufferLen);
    iEncipher = AsymmetricEncipher::CreateEncipher("SM2");
    if (iEncipher == nullptr) {
        Cyber_error_message("CreateEncipher SM2 fail.");
        goto cleanup;
    }
    if (!iEncipher->DecryptData(iKeyPair, vCipherData, vBuffer)) {
        Cyber_error_message("DecryptData fail.");
        goto cleanup;
    }
    if (!(cipherCtx = EVP_CIPHER_CTX_new())) {
        Cyber_error_message("EVP_CIPHER_CTX_new fail.");
        goto cleanup;
    }
    if ((EVP_CipherInit_ex(cipherCtx, EVP_sm4_ecb(), nullptr, vBuffer.data(),
                           nullptr, 0) != 1)) {
        Cyber_error_message("EVP_CipherInit_ex fail.");
        goto cleanup;
    }
    if (EVP_Cipher(cipherCtx, ucPrivateKey,
               pEnvelopedKeyBlob->cbEncryptedPriKey + 32, 32) != 1) {
        Cyber_error_message("EVP_Cipher fail.");
        goto cleanup;
    }
    vPlainData.assign(ucPrivateKey, ucPrivateKey + 32);
    res = true;
cleanup:
    OPENSSL_free(pucBuffer);
    EVP_CIPHER_CTX_free(cipherCtx);
    BN_free(c1);
    BN_free(c2);
    ASN1_OCTET_STRING_free(ciphertext_st.C3);
    ASN1_OCTET_STRING_free(ciphertext_st.C2);
    return res;
}
