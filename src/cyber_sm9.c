//
// Create by Gerryfan on 2025/02/07
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include <stdio.h>
#include "cyber_pki.h"
#include "external/cyber_saf.h"
#include "external/cyber_thread.h"
#include "crypto/sm9/sm9.h"
#include "crypto/sm9/sm9_obj_mac.h"
#include <openssl/objects.h>
#include <openssl/err.h>
#include "crypto/sm9/sm9_err.h"
#include <openssl/opensslv.h>
#include <string.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
// OpenSSL 3.0 及以上版本
#define DECLARE_ASN1_ENCODE_FUNCTIONS_const(type, itname, name) \
    DECLARE_ASN1_ENCODE_FUNCTIONS(type, itname, name)
#else
// OpenSSL 1.1.x 及以下版本
// 保留原有的 DECLARE_ASN1_ENCODE_FUNCTIONS_const 宏定义
#endif

#define CY_LOG_STUB()  printf("[%s:%d] %s\n", __FILE__, __LINE__, __FUNCTION__) 
void printHex(const unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}
int add_nid_func(const char *oid, const char *sn, const char *ln)
{
    int new_nid = OBJ_create(oid,sn, ln);
    if(new_nid == NID_undef)
    {
        fprintf(stderr, "OBJ_create failed\n");
        return -1;
    }
    //use new id 
    ASN1_OBJECT *obj = OBJ_nid2obj(new_nid);
    if (obj == NULL) {
        fprintf(stderr, "Failed to get ASN1_OBJECT for new NID\n");
        return -1;
    }

    char buf[256];
    int len = OBJ_obj2txt(buf, sizeof(buf), obj, 1);
    if (len < 0) {
        fprintf(stderr, "Failed to convert ASN1_OBJECT to text\n");
        return -1;
    }
    printf("New %s NID: %d, OID: %s\n",sn, new_nid, buf);
    
    return 0;
}

int sm9_nid_init(void)
{
    //int new_nid = OBJ_create("1.2.156.10197.1.302.6.1",SN_sm9bn256v1, "SM9 BN256v1");
    static int flag_init = 0;
    if (flag_init) {
        return 0;
    }
    int rv = add_nid_func("1.2.156.10197.1.302.6.1", SN_sm9bn256v1, "SM9 BN256v1");
    if (rv < 0) 
    {
        printf("Failed to add NID for SM9 BN256v1\n");
        return rv;
    }
    rv = add_nid_func("1.2.156.10197.1.302.1", SN_sm9sign, "SM9 Sign");
    if (rv < 0)
    {
        printf("Failed to add NID for SM9 Sign\n");
        return rv;
    }
    rv = add_nid_func("1.2.156.10197.1.302.3", SN_sm9encrypt, "SM9 Encrypt");
    if (rv < 0)
    {
        printf("Failed to add NID for SM9 Sign\n");
        return rv;
    }
    rv = add_nid_func("1.2.156.10197.1.302.4.1", SN_sm9hash1_with_sm3, "SM9 Hash1 with SM3");
    if (rv < 0)  
    {
        printf("Failed to add NID for SM9 Hash1 with SM3\n");
        return rv;
    }
    rv = add_nid_func("1.2.156.10197.1.302.3.1", SN_sm9encrypt_with_sm3_xor, "SM9 Encrypt with SM3 XOR");
    if (rv < 0)
    {
        printf("Failed to add NID for SN_sm9encrypt_with_sm3_xor\n");
        return rv;
    }

    rv = add_nid_func("1.2.156.10197.1.302.5.1", SN_sm9kdf_with_sm3, "SM9 KDF with SM3");
    if (rv < 0)
    {
        printf("Failed to add NID for SN_sm9kdf_with_sm3\n");
        return rv;
    }
    
    flag_init = 1;
    return 0;
}
int CY_GenSM9MasterKeyPair(
        unsigned int uiMasterKeyType,
        unsigned char *pucMasterPublicKey,
        unsigned int *uiMasterPublicKeyLen,
        unsigned char *pucMasterPrivateKey,
        unsigned int *uiMasterPrivateKeyLen)
{
    CY_Lock(0);
    int rv = 0;
    int len = 0;
    if (sm9_nid_init() < 0) {
		rv = -1;
		goto end;
    }
    SM9PublicParameters *mpk = NULL;
	SM9MasterSecret *msk = NULL;
    if (uiMasterKeyType == 0)
    {
        rv = SM9_setup(NID_sm9bn256v1, NID_sm9sign, NID_sm9hash1_with_sm3, &mpk, &msk);
    }
    else
    {
        rv = SM9_setup(NID_sm9bn256v1, NID_sm9encrypt, NID_sm9hash1_with_sm3, &mpk, &msk);
    }
    if(rv == NULL)
    {
		ERR_print_errors_fp(stderr);
		goto end;
	}
    if(msk != NULL)
    {
        len = BN_bn2bin(msk->masterSecret, pucMasterPrivateKey);
        *uiMasterPublicKeyLen =  msk->pointPpub->length;
        memcpy(pucMasterPublicKey,msk->pointPpub->data,msk->pointPpub->length);
        *uiMasterPrivateKeyLen = len;
    }
    rv = 0;
    CY_UnLock(0);
end:
    SM9MasterSecret_free(msk);
    SM9PublicParameters_free(mpk);
    return rv;
}

int CY_CalMasterPublicKey(unsigned int uiMasterKeyType, SM9MasterSecret *msk)
{
    /* Ppubs = k * P2 in E'(F_p^2) */
    int ret = 0;
	int point_form = POINT_CONVERSION_UNCOMPRESSED;
    BN_CTX *ctx = NULL;
    
    unsigned char buf[129];
    int len  = sizeof(buf);
    ctx = BN_CTX_new();
    if (!ctx) {
        SM9err(SM9_F_SM9_GENERATE_MASTER_SECRET, ERR_R_MALLOC_FAILURE);
        ret = -1;
        goto end;
    }
    BN_CTX_start(ctx);
    if(uiMasterKeyType == 0)
    {
        point_t Ppubs;
        const BIGNUM *p = SM9_get0_prime();
        if (!point_init(&Ppubs, ctx)
            || !point_mul_generator(&Ppubs, msk->masterSecret, p, ctx)
            || !point_to_octets(&Ppubs, buf, ctx)) {
            SM9err(SM9_F_SM9_GENERATE_MASTER_SECRET, SM9_R_TWIST_CURVE_ERROR);
            point_cleanup(&Ppubs);
            ret = -1;
            goto end;
        }
        len = 129;
        point_cleanup(&Ppubs);

    }
    else
    {
        /* Ppube = k * P1 in E(F_p) */
		EC_GROUP *group = NULL;
		EC_POINT *Ppube = NULL;

		//if (!(group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1))
		if (!(group = init_sm9_curve_group_order(NID_sm9bn256v1))
			|| !(Ppube = EC_POINT_new(group))
			|| !EC_POINT_mul(group, Ppube, msk->masterSecret, NULL, NULL, ctx)
			|| !(len = EC_POINT_point2oct(group, Ppube, point_form, buf, len, ctx))) {
			SM9err(SM9_F_SM9_GENERATE_MASTER_SECRET, SM9_R_EC_LIB);
			EC_GROUP_free(group);
			EC_POINT_free(Ppube);
			goto end;
		}

		EC_GROUP_free(group);
		EC_POINT_free(Ppube);
    }
    if (!(msk->pointPpub = ASN1_OCTET_STRING_new())) {
    SM9err(SM9_F_SM9_GENERATE_MASTER_SECRET, ERR_R_MALLOC_FAILURE);
    ret = -1;
    goto end;
    }
    if (!ASN1_OCTET_STRING_set(msk->pointPpub, buf, (int)len)) {
        ERR_print_errors_fp(stderr);
        ret = -1;
        goto end;
    }
end:
    if(ctx)
    {
        BN_CTX_end(ctx);
    }
    if(ctx != NULL)
    {
        //BN_CTX_free(ctx);//Gerryfan
    }
    OPENSSL_cleanse(buf, sizeof(buf));
    return ret;
}
        
int CY_GenSM9UserKeyPair(
        unsigned int  uiMasterKeyType,
        unsigned char *pucMasterPrivateKey,
        unsigned int  uiMasterPrivateKeyLen,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        unsigned char *pucUserPrivateKey,
        unsigned int *uiUserPrivateKeyLen)
{
    int rv = 0;
    CY_Lock(0);

    if (sm9_nid_init() < 0) {
		rv = -1;
		goto end;
    }
    SM9PrivateKey *sk = NULL;
    SM9MasterSecret *msk = NULL;
    msk = SM9MasterSecret_new();
    if (msk == NULL) {
		rv = -1;
		goto end;
    }
    msk->masterSecret = BN_bin2bn(pucMasterPrivateKey, uiMasterPrivateKeyLen, NULL);
    if (msk->masterSecret == NULL) {
		rv = -1;
        printf("BN_bin2bn failed\n");
		goto end;
    }
    
    	/* check pairing */
	msk->pairing = OBJ_nid2obj(NID_sm9bn256v1);
    if(uiMasterKeyType == 0)
    {
        msk->scheme = OBJ_nid2obj(NID_sm9sign);
    }
    else
    {
        msk->scheme = OBJ_nid2obj(NID_sm9encrypt);
    }
    msk->hash1 = OBJ_nid2obj(NID_sm9hash1_with_sm3);

     rv = CY_CalMasterPublicKey(uiMasterKeyType,msk);
     if (rv < 0) {
        ERR_print_errors_fp(stderr);
         goto end;
     }
     printf("msk->pointPpub->length is %d\n", msk->pointPpub->length);
   	/* generate private key */
	if (!(sk = SM9_extract_private_key(msk, pucUserID, uiUserIDLen))) 
    {
		printf("SM9_extract_private_key failed\n");
        ERR_print_errors_fp(stderr);
		rv = -1;
		goto end;
	}
    if(sk == NULL)
    {
        rv = -1;
        goto end;
    }
    
    int len = sk->privatePoint->length;
    printf("\n sk len is %d\n", len);
    *uiUserPrivateKeyLen = len;
    printHex(sk->privatePoint->data, len);
    memcpy(pucUserPrivateKey,sk->privatePoint->data,len);
    
    CY_UnLock(0);
end:
    if(msk != NULL)
    {
        SM9MasterSecret_free(msk);
    }
    if(sk != NULL)
    {
        SM9PrivateKey_free(sk);
    }
    return rv;
}

int CY_SM9Sign(
        unsigned char *pucMasterPublicKey,
        unsigned int uiMasterPublicKeyLen,
        unsigned char *pucUserPrivateKey,
        unsigned int uiUserPrivateKeyLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int *puiSignatureLen)
{
    int rv = 0;
    CY_Lock(0);
    size_t oulen = 0;
    SM9PrivateKey *sk = NULL;
    sk = SM9PrivateKey_new();
    if (sk == NULL) {
		rv = -1;
		goto end;
    }
    sk->privatePoint = ASN1_STRING_new();
    if (sk->privatePoint == NULL) {
		rv = -1;
		goto end;
    }
    ASN1_STRING_set(sk->privatePoint, pucUserPrivateKey, uiUserPrivateKeyLen);
    sk->pointPpub = ASN1_STRING_new();
    if (sk->pointPpub == NULL) {
		rv = -1;
		goto end;
    }
    ASN1_STRING_set(sk->pointPpub, pucMasterPublicKey, uiMasterPublicKeyLen);
    sk->pairing = OBJ_nid2obj(NID_sm9bn256v1);
    sk->scheme = OBJ_nid2obj(NID_sm9sign);
    sk->hash1 = OBJ_nid2obj(NID_sm9hash1_with_sm3);
    sk->scheme = OBJ_nid2obj(NID_sm9sign);
    oulen = *puiSignatureLen;
    if(!SM9_sign(NID_sm3, pucInData, uiInDataLen, pucSignature, &oulen, sk))
    {
        printf("SM9_sign failed\n");
        ERR_print_errors_fp(stderr);
        rv = -1;
        goto end;
    }
    *puiSignatureLen = oulen;
    CY_UnLock(0);
end:
    SM9PrivateKey_free(sk);
    return rv;
}

int CY_SM9VerifySign(
        unsigned char *pucMasterPublicKey,
        unsigned int uiMasterPublicKeyLen,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucSignature,
        unsigned int uiSignatureLen)
{
    int rv = 0;
    SM9PublicParameters *mpk = NULL;
    if (!(mpk = SM9PublicParameters_new())) {
		SM9err(SM9_F_SM9_EXTRACT_PUBLIC_PARAMETERS, ERR_R_MALLOC_FAILURE);
		return -1;
	}
    /* check pairing */
	mpk->pairing = OBJ_nid2obj(NID_sm9bn256v1);
    mpk->scheme = OBJ_nid2obj(NID_sm9sign);
    mpk->hash1 = OBJ_nid2obj(NID_sm9hash1_with_sm3);
    mpk->pointPpub = ASN1_STRING_new();
    if (mpk->pointPpub == NULL) {
		rv = -1;
		goto end;
    }
    ASN1_STRING_set(mpk->pointPpub, pucMasterPublicKey, uiMasterPublicKeyLen);
	rv = SM9_verify(NID_sm3, pucInData, uiInDataLen, pucSignature, uiSignatureLen, mpk, pucUserID, uiUserIDLen);
	if (rv < 0) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
    rv = 0;
end:
    if(mpk != NULL)
    {
        SM9PublicParameters_free(mpk);
    }
    return rv;
}

int CY_SM9Encrypt(
        unsigned char *pucMasterPublicKey,
        unsigned int uiMasterPublicKeyLen,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int  *puiDataLen)
{
    int rv = 0;
    size_t inlen = 0, oulen = 0;
    CY_Lock(0);
    if (sm9_nid_init() < 0) {
		rv = -1;
		goto end;
    }
    SM9PublicParameters *mpk = NULL;
    if (!(mpk = SM9PublicParameters_new())) {
		SM9err(SM9_F_SM9_EXTRACT_PUBLIC_PARAMETERS, ERR_R_MALLOC_FAILURE);
		return -1;
    }
        /* check pairing */
	mpk->pairing = OBJ_nid2obj(NID_sm9bn256v1);
    mpk->scheme = OBJ_nid2obj(NID_sm9encrypt);
    mpk->hash1 = OBJ_nid2obj(NID_sm9hash1_with_sm3);
    mpk->pointPpub = ASN1_STRING_new();
    if (mpk->pointPpub == NULL) {
		rv = -1;
		goto end;
    }
    ASN1_STRING_set(mpk->pointPpub, pucMasterPublicKey, uiMasterPublicKeyLen);
    inlen = uiInDataLen;
    oulen = *puiDataLen;
    if (!SM9_encrypt(NID_sm9encrypt_with_sm3_xor, pucInData, inlen,
		pucData, &oulen, mpk, pucUserID, uiUserIDLen)) {
		ERR_print_errors_fp(stderr);
        rv = -1;
		goto end;
	}
    *puiDataLen = oulen;
    rv = 0;
    CY_UnLock(0);
end:
    SM9PublicParameters_free(mpk);
    return rv;
}

int CY_SM9Decrypt(
        unsigned char *pucUserPrivateKey,
        unsigned int uiUserPrivateKeyLen,
        unsigned char *pucUserID,
        unsigned int uiUserIDLen,
        unsigned char *pucInData,
        unsigned int uiInDataLen,
        unsigned char *pucData,
        unsigned int *puiDataLen)
{
    int rv = 0;
    CY_Lock(0);
    if (sm9_nid_init() < 0) {
		rv = -1;
		goto end;
    }
    size_t inlen = 0, oulen = 0;
    SM9PrivateKey *sk = NULL;
    sk = SM9PrivateKey_new();
    if (sk == NULL) {
		rv = -1;
		goto end;
    }
    sk->privatePoint = ASN1_STRING_new();
    if (sk->privatePoint == NULL) {
		rv = -1;
		goto end;
    }
    ASN1_STRING_set(sk->privatePoint, pucUserPrivateKey, uiUserPrivateKeyLen);
    sk->pairing = OBJ_nid2obj(NID_sm9bn256v1);
    sk->scheme = OBJ_nid2obj(NID_sm9encrypt);
    sk->hash1 = OBJ_nid2obj(NID_sm9hash1_with_sm3);
    sk->identity = ASN1_STRING_new();
    if (sk->identity == NULL) {
		rv = -1;
		goto end;
    }
    ASN1_STRING_set(sk->identity, pucUserID, uiUserIDLen);
    inlen = uiInDataLen;
    oulen = *puiDataLen;
	if (!SM9_decrypt(NID_sm9encrypt_with_sm3_xor, pucInData, uiInDataLen,
		pucData, &oulen, sk)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
    *puiDataLen = oulen;
    CY_UnLock(0);
end:
    SM9PrivateKey_free(sk);
    return rv;
}