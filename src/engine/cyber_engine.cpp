//
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
// reference ibmca

#include "cyber_engine.h"
#include <cstring>
#include <openssl/engine.h>
#include "cyber_pkey.h"
#include "engine_config.h"

// Constants used when creating the ENGINE
static const char *engine_security_id   = "cyber_security";
static const char *engine_security_name = "cyber_security_name";

static int cyber_crypto_algos[] = {
        EVP_PKEY_RSA,
        EVP_PKEY_EC,
        EVP_PKEY_SM2,
        0
};

#define MAX_CIPHER_NIDS sizeof(cyber_crypto_algos)

static int size_pkey_meths_list = 0;

struct crypto_pair {
    int nids[MAX_CIPHER_NIDS];
    const void *crypto_meths[MAX_CIPHER_NIDS];
};

static struct crypto_pair cyber_pkey_meths_lists;

// EVP_PKEY methods
// Set digest method, cipher method ...
inline static int set_engine_prop(ENGINE *e, int algo_id, int *pkey_nid_cnt)
{
    (void)e;
    switch (algo_id) {
        case EVP_PKEY_RSA:
            cyber_pkey_meths_lists.nids[*pkey_nid_cnt] = EVP_PKEY_RSA;
            cyber_pkey_meths_lists.crypto_meths[(*pkey_nid_cnt)++] = cyber_rsa();
            break;
        case EVP_PKEY_EC:
            cyber_pkey_meths_lists.nids[*pkey_nid_cnt] = EVP_PKEY_EC;
            cyber_pkey_meths_lists.crypto_meths[(*pkey_nid_cnt)++] = cyber_ecc();
            break;
        case EVP_PKEY_SM2:
            cyber_pkey_meths_lists.nids[*pkey_nid_cnt] = EVP_PKEY_SM2;
            cyber_pkey_meths_lists.crypto_meths[(*pkey_nid_cnt)++] = cyber_sm2();
            break;
        default:
            break;
    }
    size_pkey_meths_list = *pkey_nid_cnt;
    return 1;
}

static int cyber_usable_pkey_meths(const int **nids)
{
    if (nids)
        *nids = cyber_pkey_meths_lists.nids;

    return (int)size_pkey_meths_list;
}

static int engine_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                                   const int **nids, int nid)
{
    int i;
    (void )e;
    if (!pmeth)
        return (cyber_usable_pkey_meths(nids));
    *pmeth = nullptr;
    for (i = 0; i < size_pkey_meths_list; i++) {
        if (nid == cyber_pkey_meths_lists.nids[i]) {
            *pmeth = (EVP_PKEY_METHOD *)cyber_pkey_meths_lists.crypto_meths[i];
            break;
        }
    }

    return (*pmeth != nullptr);
}

static int set_supported_meths(ENGINE *e)
{
    int rv = 0;
    int pkey_nid_cnt = 0;
    int size_algos = sizeof(cyber_crypto_algos) / sizeof(int);
    for (int i = 0; i < size_algos; ++i) {
        set_engine_prop(e, cyber_crypto_algos[i], &pkey_nid_cnt);
    }
    if (!ENGINE_set_pkey_meths(e, engine_pkey_meths)) {
        goto err;
    }
    rv = 1;
err:
    return rv;
}

static int engine_init(ENGINE *engine) {
#if ENGINE_DEBUG
    printf("%s\n", __FUNCTION__ );
#endif
    if (!set_supported_meths(engine))
        goto err;
    return 1;
err:
    return 0;
}

static int engine_destory(ENGINE *engine) {
#if ENGINE_DEBUG
    printf("%s\n", __FUNCTION__ );
#endif
    (void )engine;
// Calling both destory will result in a memory exception
//    cyber_rsa_destory();
//    cyber_ecc_destory();
    return 1;
}

static int engine_finish(ENGINE *engine) {
#if ENGINE_DEBUG
    printf("%s\n", __FUNCTION__ );
#endif
    (void )engine;
    return 1;
}

// This internal function is used by engine.
// This method determines which algorithms support the engine.
static int bind_helper(ENGINE *engine)
{
#if ENGINE_DEBUG
    printf("Engine: %s\n", __FUNCTION__ );
#endif
    if (!ENGINE_set_id(engine, engine_security_id) ||
        !ENGINE_set_name(engine, engine_security_name) ||
        !ENGINE_set_destroy_function(engine, engine_destory) ||
        !ENGINE_set_init_function(engine, engine_init) ||
        !ENGINE_set_finish_function(engine, engine_finish))
        return 0;

    return 1;
}

static ENGINE *engine_cyber()
{
    ENGINE *ret = ENGINE_new();
    if (!ret)
        return nullptr;
    if (!bind_helper(ret)) {
        ENGINE_free(ret);
        return nullptr;
    }
#if ENGINE_DEBUG
    printf("Engine bind success: %s\n", __FUNCTION__ );
#endif
    return ret;
}

void ENGINE_load_cyber()
{
#if ENGINE_DEBUG
    printf("%s\n", __FUNCTION__ );
#endif
    ENGINE *toadd = engine_cyber();
    if (!toadd)
    {
  #if ENGINE_DEBUG
    printf("load engine iwall failed\n");
#endif      
        return;
    }
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}

void ENGINE_unload_cyber()
{
    ENGINE *engine = ENGINE_by_id(engine_security_id);
    if (engine) {
        ENGINE_remove(engine);
        ENGINE_free(engine);
    }
}

static int bind_fn(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_security_id) != 0)) {
        return 0;
    }
    if (!bind_helper(e)) {
        return 0;
    }
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
