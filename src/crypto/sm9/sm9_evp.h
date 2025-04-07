#ifndef __SM9_EVP_H__
#define __SM9_EVP_H__
#include "sm9_lcl.h"
#include <openssl/evp.h>
#ifdef __cpulsplus
extern "C" {
#endif

# define EVP_R_EXPECTING_A_SM9_KEY                        180
# define EVP_R_EXPECTING_A_SM9_MASTER_KEY                 181


struct SM9_MASTER_KEY_st;
int EVP_PKEY_set1_SM9_MASTER(EVP_PKEY *pkey, struct SM9_MASTER_KEY_st *key);
struct SM9_MASTER_KEY_st *EVP_PKEY_get0_SM9_MASTER(EVP_PKEY *pkey);
struct SM9_MASTER_KEY_st *EVP_PKEY_get1_SM9_MASTER(EVP_PKEY *pkey);

#define EVP_PKEY_set1_SM9MasterSecret(pk,k) EVP_PKEY_set1_SM9_MASTER(pk,k)
#define EVP_PKEY_get0_SM9MasterSecret(pk) EVP_PKEY_get0_SM9_MASTER(pk)
#define EVP_PKEY_get1_SM9MasterSecret(pk) EVP_PKEY_get1_SM9_MASTER(pk)
#define EVP_PKEY_set1_SM9PublicParameters(pk,k) EVP_PKEY_set1_SM9_MASTER(pk,k)
#define EVP_PKEY_get0_SM9PublicParameters(pk) EVP_PKEY_get0_SM9_MASTER(pk)
#define EVP_PKEY_get1_SM9PublicParameters(pk) EVP_PKEY_get1_SM9_MASTER(pk)
struct SM9_KEY_st;
int EVP_PKEY_set1_SM9(EVP_PKEY *pkey, struct SM9_KEY_st *key);
struct SM9_KEY_st *EVP_PKEY_get0_SM9(EVP_PKEY *pkey);
struct SM9_KEY_st *EVP_PKEY_get1_SM9(EVP_PKEY *pkey);
#define EVP_PKEY_set1_SM9PrivateKey(pk,k) EVP_PKEY_set1_SM9(pk,k)
#define EVP_PKEY_get0_SM9PrivateKey(pk,k) EVP_PKEY_get0_SM9(pk)
#define EVP_PKEY_get1_SM9PrivateKey(pk,k) EVP_PKEY_get1_SM9(pk)
#define EVP_PKEY_set1_SM9PublicKey(pk,k) EVP_PKEY_set1_SM9(pk,k)
#define EVP_PKEY_get0_SM9PublicKey(pk,k) EVP_PKEY_get0_SM9(pk)
#define EVP_PKEY_get1_SM9PublicKey(pk,k) EVP_PKEY_get1_SM9(pk)


#define EVP_PKEY_assign_SM9_MASTER(pkey,sm9) EVP_PKEY_assign((pkey),EVP_PKEY_SM9_MASTER, (char *)(sm9))
#define EVP_PKEY_assign_SM9(pkey,sm9) EVP_PKEY_assign((pkey),EVP_PKEY_SM9, (char *)(sm9))
#define EVP_PKEY_assign_SM9MasterSecret(pkey,sm9) EVP_PKEY_assign_SM9_MASTER(pkey,sm9)
#define EVP_PKEY_assign_SM9PublicParameters(pkey,sm9) EVP_PKEY_assign_SM9_MASTER(pkey,sm9)
#define EVP_PKEY_assign_SM9PrivateKey(pkey,sm9) EVP_PKEY_assign_SM9(pkey,sm9)
#define EVP_PKEY_assign_SM9PublicKey(pkey,sm9) EVP_PKEY_assign_SM9(pkey,sm9)



#ifdef __cpulsplus
}
#endif

#endif /* __SM9_EVP_H__ */