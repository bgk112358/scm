#include "sm9_evp.h"
#include "sm9.h"
#include "sm9_obj_mac.h"
#include <openssl/err.h>

#include "internal/evp_int.h"

SM9_MASTER_KEY *EVP_PKEY_get0_SM9_MASTER(EVP_PKEY *pkey)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if(EVP_PKEY_get_id(pkey) != EVP_PKEY_SM9_MASTER)
    #else
    if (pkey->type != EVP_PKEY_SM9_MASTER) 
    #endif 
    {
        return NULL;
    }
    return pkey->pkey.sm9_master;
}

SM9_KEY *EVP_PKEY_get0_SM9(EVP_PKEY *pkey)
{
     #if ENABLE_OPENSSL_NO_DEPRECATED_3_0
    if(EVP_PKEY_get_id(pkey) != EVP_PKEY_SM9)
    #else
	if (pkey->type != EVP_PKEY_SM9) 
    #endif
    {
//		EVPerr(EVP_F_EVP_PKEY_GET0_SM9, EVP_R_EXPECTING_A_SM9_KEY);
		return NULL;
	}
	return pkey->pkey.sm9;
}