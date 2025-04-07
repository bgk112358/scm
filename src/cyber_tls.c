// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "cyber_tls.h"
#include "external/cyber_saf.h"
#include "external/cyber_saf_tls.h"
#include "external/cyber_thread.h"
#include <openssl/ssl.h>

// The security chip is used during the SSL connection.
// Can`t call CY_SAF_Logout function.
int CY_GetSSLContext(
        void *hAppHandle,
        unsigned char *pucContainerName,
        unsigned int uiContainerNameLen,
        unsigned char *pucPin,
        unsigned int uiPinLen,
        void ** ctx) {
    CY_Lock(0);
    int rv = CY_SAF_Login(
            hAppHandle,
            0,
            pucContainerName,
            uiContainerNameLen,
            pucPin,
            uiPinLen,
            NULL);
    if (rv != CYBER_R_SUCCESS) {
        goto cleanup;
    }
    rv = CY_SAF_GetSSLContext(
            hAppHandle,
            pucContainerName,
            uiContainerNameLen,
            ctx);
cleanup:
    CY_UnLock(0);
    return rv;
}


__attribute__((unused))
int CY_HTTP_TLS_PostRequest_Internal(
        void          * hAppHandle,
        unsigned char * pucContainerName,
        unsigned int    uiContainerNameLen,
        unsigned char * pucPin,
        unsigned int    uiPinLen,
        const char *requestUrl,
        const char *requestHeader[], int headerCount,
        const unsigned char *postFields, unsigned int postFieldsLen,
        char *responseBuffer, unsigned int* bufferLen) {
    if (hAppHandle == NULL || requestHeader == NULL ||
        postFields == NULL || bufferLen == NULL) {
        return CYBER_R_ERR_INPUT;
    }
    *bufferLen = 1;
    printf("%s, %s", pucContainerName, pucPin);
    printf("%d, %d, %d, %d", uiContainerNameLen, uiPinLen, headerCount, postFieldsLen);
    printf("%s, %s", requestUrl, responseBuffer);
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    BIO *bio = BIO_new_ssl_connect(ctx);
    SSL_CTX_free(ctx);
    BIO_free(bio);
    return CYBER_R_ERR;
}