/* ====================================================================
 * Copyright (c) 2016 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <openssl/err.h>
#include <openssl/objects.h>
#include "sm9.h"
#include "sm9_lcl.h"
#include "sm9_obj_mac.h"
#include "sm9_err.h"

extern EC_GROUP* init_sm9_curve_group_order(int nid);

SM9MasterSecret *SM9_generate_master_secret(int pairing, int scheme, int hash1)
{
	SM9MasterSecret *ret = NULL;
	SM9MasterSecret *msk = NULL;
	BN_CTX *ctx = NULL;
	const BIGNUM *n = SM9_get0_order();
	const BIGNUM *p = SM9_get0_prime();
	int point_form = POINT_CONVERSION_UNCOMPRESSED;
	unsigned char buf[129];
	size_t len = sizeof(buf);
	if (!(msk = SM9MasterSecret_new())
		|| !(ctx = BN_CTX_new())) {
		SM9err(SM9_F_SM9_GENERATE_MASTER_SECRET, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	BN_CTX_start(ctx);
	
	/* set pairing type */
	switch (pairing) {
	case NID_sm9bn256v1:
		if (!(msk->pairing = OBJ_nid2obj(pairing))) {
			SM9err(SM9_F_SM9_GENERATE_MASTER_SECRET, ERR_R_OBJ_LIB);
			goto end;
		}
		break;
	default:
		SM9err(SM9_F_SM9_GENERATE_MASTER_SECRET, SM9_R_INVALID_PAIRING_TYPE);
		goto end;
	}
	/* set helper functions */
	switch (scheme) {
	case NID_sm9sign:
	case NID_sm9encrypt:
	case NID_sm9keyagreement:
		if (!(msk->scheme = OBJ_nid2obj(scheme))) {
			SM9err(SM9_F_SM9_GENERATE_MASTER_SECRET, ERR_R_OBJ_LIB);
			goto end;
		}
		break;
	default:
		SM9err(SM9_F_SM9_GENERATE_MASTER_SECRET, SM9_R_INVALID_SCHEME);
		goto end;
	}
	/* set hash1 */
	switch (hash1) {
	case NID_sm9hash1_with_sm3:
	case NID_sm9hash1_with_sha256:
		if (!(msk->hash1 = OBJ_nid2obj(hash1))) {
			SM9err(SM9_F_SM9_GENERATE_MASTER_SECRET, ERR_R_OBJ_LIB);
			goto end;
		}
		break;
	default:
		SM9err(SM9_F_SM9_GENERATE_MASTER_SECRET, SM9_R_INVALID_HASH1);
		goto end;
	}
	/* generate master secret k = rand(1, n - 1) */
	do {

		if (!(msk->masterSecret = BN_new())) {
			SM9err(SM9_F_SM9_GENERATE_MASTER_SECRET, ERR_R_MALLOC_FAILURE);
			goto end;
		}
		if (!BN_rand_range(msk->masterSecret, n)) {
			SM9err(SM9_F_SM9_GENERATE_MASTER_SECRET, ERR_R_BN_LIB);
			goto end;
		}
	} while (BN_is_zero(msk->masterSecret));

	/* generate master public point */
	if (scheme == NID_sm9sign) {

		/* Ppubs = k * P2 in E'(F_p^2) */
		point_t Ppubs;

		if (!point_init(&Ppubs, ctx)
			|| !point_mul_generator(&Ppubs, msk->masterSecret, p, ctx)
			|| !point_to_octets(&Ppubs, buf, ctx)) {
			SM9err(SM9_F_SM9_GENERATE_MASTER_SECRET, SM9_R_TWIST_CURVE_ERROR);
			point_cleanup(&Ppubs);
			goto end;
		}

		len = 129;
		point_cleanup(&Ppubs);
		if(ctx != NULL)
		{
			printf("ctx is not NULL");
		}

	} else if (scheme == NID_sm9keyagreement
		|| scheme == NID_sm9encrypt) {

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

	} else {
		SM9err(SM9_F_SM9_GENERATE_MASTER_SECRET, SM9_R_INVALID_SCHEME);
		goto end;
	}

	if (!(msk->pointPpub = ASN1_OCTET_STRING_new())) {
		SM9err(SM9_F_SM9_GENERATE_MASTER_SECRET, ERR_R_MALLOC_FAILURE);
		goto end;
	}
	if (!ASN1_OCTET_STRING_set(msk->pointPpub, buf, (int)len)) {
		ERR_print_errors_fp(stderr);
		goto end;
	}
	ret = msk;
	msk = NULL;
end:
	SM9MasterSecret_free(msk);
	
	if (ctx) {
		BN_CTX_end(ctx);
	}

	if(ctx) 
	{	
		//BN_CTX_free(ctx);//Gerryfan
		ctx = NULL;
	}

	OPENSSL_cleanse(buf, sizeof(buf));
	return ret;
}

SM9PublicParameters *SM9_extract_public_parameters(SM9MasterSecret *msk)
{
	SM9PublicParameters *ret = NULL;
	SM9PublicParameters *mpk = NULL;

	if (!(mpk = SM9PublicParameters_new())) {
		SM9err(SM9_F_SM9_EXTRACT_PUBLIC_PARAMETERS, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	if (!(mpk->pairing = OBJ_dup(msk->pairing))
		|| !(mpk->scheme = OBJ_dup(msk->scheme))
		|| !(mpk->hash1 = OBJ_dup(msk->hash1))
		|| !(mpk->pointPpub = ASN1_OCTET_STRING_dup(msk->pointPpub))) {
		SM9err(SM9_F_SM9_EXTRACT_PUBLIC_PARAMETERS, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	ret = mpk;
	mpk = NULL;

end:
	SM9PublicParameters_free(mpk);
	return ret;
}

int SM9_setup(int pairing, int scheme, int hash1,
	SM9PublicParameters **pmpk, SM9MasterSecret **pmsk)
{
	int ret = 0;
	SM9MasterSecret *msk = NULL;
	SM9PublicParameters *mpk = NULL;

	if (!(msk = SM9_generate_master_secret(pairing, scheme, hash1))
		|| !(mpk = SM9_extract_public_parameters(msk))) {
		goto end;
	}

	*pmsk = msk;
	*pmpk = mpk;
	msk = NULL;
	mpk = NULL;
	ret = 1;

end:
	SM9MasterSecret_free(msk);
	SM9PublicParameters_free(mpk);
	return ret;
}

typedef struct {
    int field_type,             /* either NID_X9_62_prime_field or
                                 * NID_X9_62_characteristic_two_field */
     seed_len, param_len;
    unsigned int cofactor;      /* promoted to BN_ULONG */
} EC_CURVE_DATA;
typedef struct _ec_list_element_st {
    int nid;
    const EC_CURVE_DATA *data;
    const EC_METHOD *(*meth) (void);
    const char *comment;
} ec_list_element;



#ifndef OPENSSL_NO_SM9
static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 32 * 6];
} _EC_SM9_BN_256V1 = {
    {
        NID_X9_62_prime_field, 0, 32, 1
    },
    {
        /* no seed */
        /* p */
        0xB6, 0x40, 0x00, 0x00, 0x02, 0xA3, 0xA6, 0xF1, 0xD6, 0x03, 0xAB, 0x4F,
        0xF5, 0x8E, 0xC7, 0x45, 0x21, 0xF2, 0x93, 0x4B, 0x1A, 0x7A, 0xEE, 0xDB,
        0xE5, 0x6F, 0x9B, 0x27, 0xE3, 0x51, 0x45, 0x7D,
        /* a */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* b */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
	/* x */
	0x93, 0xDE, 0x05, 0x1D, 0x62, 0xBF, 0x71, 0x8F, 0xF5, 0xED, 0x07, 0x04,
        0x48, 0x7D, 0x01, 0xD6, 0xE1, 0xE4, 0x08, 0x69, 0x09, 0xDC, 0x32, 0x80,
        0xE8, 0xC4, 0xE4, 0x81, 0x7C, 0x66, 0xDD, 0xDD,
	/* y */
	0x21, 0xFE, 0x8D, 0xDA, 0x4F, 0x21, 0xE6, 0x07, 0x63, 0x10, 0x65, 0x12,
	0x5C, 0x39, 0x5B, 0xBC, 0x1C, 0x1C, 0x00, 0xCB, 0xFA, 0x60, 0x24, 0x35,
	0x0C, 0x46, 0x4C, 0xD7, 0x0A, 0x3E, 0xA6, 0x16,
	/* order */
        0xB6, 0x40, 0x00, 0x00, 0x02, 0xA3, 0xA6, 0xF1, 0xD6, 0x03, 0xAB, 0x4F,
        0xF5, 0x8E, 0xC7, 0x44, 0x49, 0xF2, 0x93, 0x4B, 0x18, 0xEA, 0x8B, 0xEE,
        0xE5, 0x6E, 0xE1, 0x9C, 0xD6, 0x9E, 0xCF, 0x25,
   }
};
#endif

const ec_list_element curve_list_sm9[] = {
    {NID_sm9bn256v1, &_EC_SM9_BN_256V1.h, 0,
     "SM9 BN curve over a 256 bit prime field"},
};

//Gerryfan
EC_GROUP* init_sm9_curve_group_order(int nnid) //const ec_list_element curve
{
	EC_GROUP *group = NULL;
    EC_POINT *P = NULL;
    BN_CTX *ctx = NULL;
	ec_list_element curve = curve_list_sm9[0];
    BIGNUM *p = NULL, *a = NULL, *b = NULL, *x = NULL, *y = NULL, *order =
        NULL;
    int ok = 0;
    int seed_len, param_len;
    const EC_METHOD *meth;
    const EC_CURVE_DATA *data;
    const unsigned char *params;

    /* If no curve data curve method must handle everything */
    if (curve.data == NULL)
        return EC_GROUP_new(curve.meth != NULL ? curve.meth() : NULL);

    if ((ctx = BN_CTX_new()) == NULL) {
        ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    data = curve.data;
    seed_len = data->seed_len;
    param_len = data->param_len;
    params = (const unsigned char *)(data + 1); /* skip header */
    params += seed_len;         /* skip seed */

    if ((p = BN_bin2bn(params + 0 * param_len, param_len, NULL)) == NULL
        || (a = BN_bin2bn(params + 1 * param_len, param_len, NULL)) == NULL
        || (b = BN_bin2bn(params + 2 * param_len, param_len, NULL)) == NULL) {
        ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_BN_LIB);
        goto err;
    }

    if(curve.meth != 0) 
	{
		printf("======>>>>> curve.meth != 0\n");
        meth = curve.meth();
        if (((group = EC_GROUP_new(meth)) == NULL) 
            //||(!(group->meth->group_set_curve(group, p, a, b, ctx)))
			) 
			{
            ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
            goto err;
        }
    } else if (data->field_type == NID_X9_62_prime_field) {
        if ((group = EC_GROUP_new_curve_GFp(p, a, b, ctx)) == NULL) {
            ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
            goto err;
        }
    }
#ifndef OPENSSL_NO_EC2M
    else {                      /* field_type ==
                                 * NID_X9_62_characteristic_two_field */

        if ((group = EC_GROUP_new_curve_GF2m(p, a, b, ctx)) == NULL) {
            ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
            goto err;
        }
    }
#endif

    if ((P = EC_POINT_new(group)) == NULL) {
        ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
        goto err;
    }

    if ((x = BN_bin2bn(params + 3 * param_len, param_len, NULL)) == NULL
        || (y = BN_bin2bn(params + 4 * param_len, param_len, NULL)) == NULL) {
        ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_BN_LIB);
        goto err;
    }
    if (!EC_POINT_set_affine_coordinates_GFp(group, P, x, y, ctx)) {
        ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
        goto err;
    }
    if ((order = BN_bin2bn(params + 5 * param_len, param_len, NULL)) == NULL
        || !BN_set_word(x, (BN_ULONG)data->cofactor)) {
        ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_BN_LIB);
        goto err;
    }
    if (!EC_GROUP_set_generator(group, P, order, x)) {
        ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
        goto err;
    }
    if (seed_len) {
        if (!EC_GROUP_set_seed(group, params - seed_len, seed_len)) {
            ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
            goto err;
        }
    }
    ok = 1;
	EC_GROUP_set_curve_name(group, nnid);//NID_sm9bn256v1
 err:
    if (!ok) {
        EC_GROUP_free(group);
        group = NULL;
    }
    EC_POINT_free(P);
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(order);
    BN_free(x);
    BN_free(y);
    return group;
}

EC_GROUP *init_sm9_curve_group(void)
{
	#if 1
    BIGNUM *p = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();

    BN_hex2bn(&p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    BN_hex2bn(&a, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE");
    BN_hex2bn(&b, "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
    EC_GROUP *group = EC_GROUP_new_curve_GFp(p, a, b, NULL);
    if (group == NULL) 
    {
        fprintf(stderr, "Failed to create EC_GROUP using EC_GROUP_new_curve_GFp\n");
        BN_free(p);
        BN_free(a);
        BN_free(b);
        return NULL;
    }
	#endif 
    
	
    // 将新创建的椭圆曲线与 NID 关联
    EC_GROUP_set_curve_name(group, NID_sm9bn256v1);

    // 打印曲线信息
    printf("EC_GROUP created successfully using EC_GROUP_new_curve_GFp\n");

    // group = EC_GROUP_new_by_curve_name(NID_sm9bn256v1);
    // if (group == NULL) {
    //     fprintf(stderr, "Failed to create EC_GROUP by curve name\n");
    //     return -1;
    // }
    
    // 释放资源
    //EC_GROUP_free(group);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    return group;
}