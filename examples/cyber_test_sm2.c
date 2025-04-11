// //
// // Create by kong
// // Copyright 2025 China Automotive Research Software Evaluating Co., Ltd.
// //

#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "cyber_pki.h"
#include "cyber_error.h"
#include "cyber_tls.h"

static void *hAppHandle = NULL;

// 文件存储路径
static char *pGlbAppFilePath = "./cyber";

// 用户容器名及 PIN 码
static unsigned char pucCyberContainerName[] = "cyber";
static unsigned int uiCyberContainerNameLen = 5;
static unsigned char pucSSLContainerName[] = "ssl";
static unsigned int uiSSLContainerNameLen = 3;
static unsigned char pucPinInfo[] = "12345678";
static unsigned int uiPinInfoLen = 8;

// 16 进制打印
void hex_print(const unsigned char *val, unsigned int len) {
    if (val == NULL) { return; }
    if (len == 0)    { return; }
    for (int i = 0; i < len; ++i) {
        printf("%02x", val[i]);
    }
    printf("\n");
}

// 读取文件
int read_file(const char *file_path, unsigned char **file_content, unsigned int *file_length) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        perror("Failed to open file");
        return -1;
    }
    fseek(file, 0, SEEK_END);
    *file_length = ftell(file);
    fseek(file, 0, SEEK_SET);
    *file_content = (unsigned char *)malloc(*file_length + 1);
    if (!*file_content) {
        perror("Failed to allocate memory");
        fclose(file);
        return -1;
    }
    size_t bytes_read = fread(*file_content, 1, *file_length, file);
    if (bytes_read != *file_length) {
        free(*file_content);
        fclose(file);
        return -1;
    }
    (*file_content)[*file_length] = '\0';
    fclose(file);
    return 0;
}

// 证书管理
int SF_CertificateManagement() {

    // 证书链
    unsigned char *pucBuffer = NULL;
    unsigned int uiBufferLen = 0;
    // 获取证书链
    // read_file("../../examples/Assets/cert_chain.pem", &pucBuffer, &uiBufferLen);
    read_file("../../examples/gmcert/root.pem", &pucBuffer, &uiBufferLen);
    // 导入证书链
    int rv = CY_ImportTrustedCertificateChain(hAppHandle, pucBuffer, uiBufferLen);
    if (pucBuffer) free(pucBuffer);
    if (rv != CY_R_SUCCESS) {
        printf("CY_ImportTrustedCertificateChain error, error code: %02x\n", rv);
        return rv;
    } else {
        printf("CY_ImportTrustedCertificateChain success\n");
    }
    // 判断用户证书是否存在
    rv = CY_GetCertificateStatus(
            hAppHandle,
            pucCyberContainerName,
            uiCyberContainerNameLen,
            pucPinInfo,
            uiPinInfoLen);
    if (rv != CY_R_SUCCESS) {
        // 生成 SM2 密钥对
        rv = CY_GenEccKeyPair(
                hAppHandle,
                pucCyberContainerName,
                uiCyberContainerNameLen,
                pucPinInfo,
                uiPinInfoLen,
                SGD_SM2,
                SGD_KEYUSAGE_SIGN,
                0);
        if (rv != CY_R_SUCCESS) {
            printf("CY_GenEccKeyPair error, error code: %02x\n", rv);
            return rv;
        } else {
            printf("CY_GenEccKeyPair success\n");
        }
        SGD_NAME_INFO nameInfo = {0};
        strcpy(nameInfo.dn_c,  "CN");
        strcpy(nameInfo.dn_s,  "Tianjin");
        strcpy(nameInfo.dn_l,  "Tianjin");
        strcpy(nameInfo.dn_o,  "Catarc");
        strcpy(nameInfo.dn_sn, "Catarc");
        strcpy(nameInfo.dn_cn, "Security");
        pucBuffer = malloc(2048);
        if (pucBuffer) {
            memset(pucBuffer, 0x00, 2048);
        }
        rv = CY_GenerateCertificateSigningRequest(
                hAppHandle,
                pucCyberContainerName,
                uiCyberContainerNameLen,
                pucPinInfo,
                uiPinInfoLen,
                &nameInfo,
                pucBuffer,
                &uiBufferLen);
        if (rv != CY_R_SUCCESS) {
            printf("CY_GenerateCertificateSigningRequest error, error code: %02x\n", rv);
            return rv;
        } else {
            printf("CY_GenerateCertificateSigningRequest success.\n");
            hex_print(pucBuffer, uiBufferLen);
        }
        if (pucBuffer) {
            free(pucBuffer);
            pucBuffer = NULL;
        }
    }
    // 导入签名密钥及签名证书
    // read_file("../../examples/Assets/sign_cert.pem", &pucBuffer, &uiBufferLen);
    read_file("../../examples/gmcert/gmTest22-cert.pem", &pucBuffer, &uiBufferLen);
    rv = CY_ImportCertificate(
            hAppHandle,
            pucSSLContainerName,
            uiSSLContainerNameLen,
            SGD_KEYUSAGE_SIGN,
            pucBuffer,
            uiBufferLen);
    if (pucBuffer) free(pucBuffer);
    pucBuffer = NULL;
    if (rv != CY_R_SUCCESS) {
        printf("CY_ImportSignCertificate error, error code: %02x\n", rv);
        return rv;
    } else {
        printf("CY_ImportSignCertificate success\n");
    }
    // read_file("../../examples/Assets/sign_key.der", &pucBuffer, &uiBufferLen);
    // read_file("../../examples/gmcert/gmTest22-privatekey.pem", &pucBuffer, &uiBufferLen);
    read_file("../../examples/gmcert/output_key_sign.der", &pucBuffer, &uiBufferLen);
    rv = CY_ImportEccKeyPair(
            hAppHandle,
            pucSSLContainerName,
            uiSSLContainerNameLen,
            pucPinInfo,
            uiPinInfoLen,
            SGD_SM2,
            SGD_KEYUSAGE_SIGN,
            pucBuffer,
            uiBufferLen);
    if (pucBuffer) free(pucBuffer);
    pucBuffer = NULL;
    if (rv != CY_R_SUCCESS) {
        printf("CY_ImportSignEccKeyPair error, error code: %02x\n", rv);
        return rv;
    } else {
        printf("CY_ImportSignEccKeyPair success\n");
    }
    // 导入加密密钥及加密证书
    // read_file("../../examples/Assets/enc_cert.pem", &pucBuffer, &uiBufferLen);
    read_file("../../examples/gmcert/gmTest33-cert.pem", &pucBuffer, &uiBufferLen);
    rv = CY_ImportCertificate(
            hAppHandle,
            pucSSLContainerName,
            uiSSLContainerNameLen,
            SGD_KEYUSAGE_ENC,
            pucBuffer,
            uiBufferLen);
    if (pucBuffer) free(pucBuffer);
    pucBuffer = NULL;
    if (rv != CY_R_SUCCESS) {
        printf("CY_ImportEncCertificate error, error code: %02x\n", rv);
        return rv;
    } else {
        printf("CY_ImportEncCertificate success\n");
    }
    // read_file("../../examples/Assets/enc_key.der", &pucBuffer, &uiBufferLen);
    // read_file("../../examples/gmcert/gmTest33-privatekey.pem", &pucBuffer, &uiBufferLen);
    read_file("../../examples/gmcert/output_key_enc.der", &pucBuffer, &uiBufferLen);
    rv = CY_ImportEccKeyPair(
            hAppHandle,
            pucSSLContainerName,
            uiSSLContainerNameLen,
            pucPinInfo,
            uiPinInfoLen,
            SGD_SM2,
            SGD_KEYUSAGE_ENC,
            pucBuffer,
            uiBufferLen);
    if (pucBuffer) free(pucBuffer);
    pucBuffer = NULL;
    if (rv != CY_R_SUCCESS) {
        printf("CY_ImportEncEccKeyPair error, error code: %02x\n", rv);
        return rv;
    } else {
        printf("CY_ImportEncEccKeyPair success\n");
    }

    pucBuffer = (unsigned char *)malloc(1024);
    uiBufferLen = 1024;
    rv = CY_ExportCertificate(
            hAppHandle,
            pucSSLContainerName,
            uiSSLContainerNameLen,
            SGD_KEYUSAGE_SIGN,
            pucBuffer,
            &uiBufferLen);
    if (rv != CY_R_SUCCESS) {
        printf("CY_ExportSignCertificate error, error code: %02x\n", rv);
        return rv;
    } else {
        printf("CY_ExportSignCertificate success\n");
        hex_print(pucBuffer, uiBufferLen);
    }
    free(pucBuffer);
    pucBuffer = NULL;

    pucBuffer = (unsigned char *)malloc(1024);
    uiBufferLen = 1024;
    rv = CY_ExportCertificate(
            hAppHandle,
            pucSSLContainerName,
            uiSSLContainerNameLen,
            SGD_KEYUSAGE_ENC,
            pucBuffer,
            &uiBufferLen);
    if (rv != CY_R_SUCCESS) {
        printf("CY_ExportSignCertificate error, error code: %02x\n", rv);
        return rv;
    } else {
        printf("CY_ExportSignCertificate success\n");
        hex_print(pucBuffer, uiBufferLen);
    }
    if (pucBuffer) {
        free(pucBuffer);
    }
    return rv;
}

int SF_CryptographicOperation() {
    int rv;
    // 对称解密
    unsigned char ucKeyData[16] = {
            0xC0, 0x1F, 0x29, 0x8C, 0x6C, 0x9B, 0x8D, 0x9D,
            0x5A, 0xDC, 0x60, 0x35, 0xFC, 0xC7, 0xC6, 0x61 };
    unsigned int uiKeyDataLen = 16;

    unsigned char ucIvData[16] = {
            0x98, 0x1E, 0x1E, 0x99, 0x1F, 0xC1, 0xCF, 0x92,
            0x15, 0x3C, 0x63, 0x9B, 0x75, 0x24, 0x18, 0xA8 };
    unsigned int uiIvDataLen = 16;
    void *hSymmKeyObj = NULL;
    rv = CY_CreateSymmKeyObj(
            &hSymmKeyObj,
            ucKeyData,
            uiKeyDataLen,
            ucIvData,
            uiIvDataLen,
            SGD_DEC,
            SGD_AES_OFB);
    if (rv != CY_R_SUCCESS) {
        printf("CY_CreateSymmKeyObj fail, fail code: %02x\n", rv);
        return rv;
    } else {
        printf("CY_CreateSymmKeyObj success\n");
    }
    unsigned char ucCipherData[] = {
            0x74, 0xa1, 0x4a, 0x13, 0x07, 0xfa, 0x6a, 0x83, 0xcb, 0xd8, 0x2e,
            0x98, 0x47, 0xda, 0xdd, 0xe7, 0x97, 0xe8, 0xd5, 0x33, 0x4d, 0x1e,
            0x1d, 0x6f, 0x0c, 0x7d, 0xae, 0x12, 0xef, 0xec, 0xf4, 0x3e, 0xcd,
            0x41, 0x8e, 0x32 };
    unsigned int uiCipherDataLen = sizeof(ucCipherData);
    unsigned char ucOutData[1024] = {0};
    unsigned int uiOutDataLen = 1024;
    rv = CY_SymmDecryptUpdate(hSymmKeyObj, ucCipherData, uiCipherDataLen, ucOutData, &uiOutDataLen);
    printf("CY_SymmDecryptUpdate: %d\n", rv);
    hex_print(ucOutData, uiOutDataLen);

    rv = CY_SymmDecryptFinal(hSymmKeyObj, ucOutData, &uiOutDataLen);
    printf("CY_SymmDecryptFinal: %d\n", rv);
    hex_print(ucOutData, uiOutDataLen);

    rv = CY_DestroySymmKeyObj(hSymmKeyObj);
    printf("CY_DestroySymmKeyObj: %d\n", rv);

    // 非对称签名验签
    unsigned char ucPublicKey[1024] = {0};
    unsigned int uiPublicKeyLen = 1024;
    rv = CY_GetEccPublicKey(
            hAppHandle,
            pucCyberContainerName,
            uiCyberContainerNameLen,
            SGD_KEYUSAGE_SIGN,
            ucPublicKey,
            &uiPublicKeyLen);
    if (rv != CY_R_SUCCESS) {
        printf("CY_GetEccPublicKey fail, fail code: %02x\n", rv);
        return rv;
    } else {
        printf("CY_GetEccPublicKey success\n");
        hex_print(ucPublicKey, uiPublicKeyLen);
    }

    unsigned char ucSignature[1024] = {0};
    unsigned int uiSignatureLen = sizeof(ucSignature);
    unsigned char ucInData[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    unsigned int  uiInDataLen = sizeof(ucInData);
    rv = CY_EccSign(
            hAppHandle,
            pucCyberContainerName,
            uiCyberContainerNameLen,
            pucPinInfo,
            uiPinInfoLen,
            SGD_SM3,
            ucInData,
            uiInDataLen,
            ucSignature,
            &uiSignatureLen);
    if (rv != CY_R_SUCCESS) {
        printf("CY_EccSign fail, fail code: %02x\n", rv);
    } else {
        printf("CY_EccSign success\n");
        hex_print(ucSignature, uiSignatureLen);
    }
    rv = CY_EccVerifySign(
            SGD_SM3,
            ucPublicKey,
            uiPublicKeyLen,
            ucInData,
            uiInDataLen,
            ucSignature,
            uiSignatureLen);
    if (rv != CY_R_SUCCESS) {
        printf("CY_EccVerifySign fail, fail code: %02x\n", rv);
        return rv;
    } else {
        printf("CY_EccVerifySign success\n");
    }
    memset(ucOutData, 0x00, 1024);
    uiOutDataLen = 1024;

    // 非对称加密解密
    rv = CY_EccEncrypt(
            ucPublicKey,
            uiPublicKeyLen,
            ucInData,
            uiInDataLen,
            ucOutData,
            &uiOutDataLen);
    if (rv != CY_R_SUCCESS) {
        printf("CY_EccEncrypt fail, fail code: %02x\n", rv);
        return rv;
    } else {
        printf("CY_EccEncrypt success\n");
        hex_print(ucOutData, uiOutDataLen);
    }

    unsigned char ucPlainData[1024] = {0};
    unsigned int uiPlainDataLen = sizeof(ucPlainData);
    rv = CY_EccDecrypt(
            hAppHandle,
            pucCyberContainerName,
            uiCyberContainerNameLen,
            pucPinInfo,
            uiPinInfoLen,
            ucOutData,
            uiOutDataLen,
            ucPlainData,
            &uiPlainDataLen);
    if (rv != CY_R_SUCCESS) {
        printf("CY_EccDecrypt fail, fail code: %02x\n", rv);
        return rv;
    } else {
        printf("CY_EccDecrypt success\n");
        hex_print(ucPlainData, uiPlainDataLen);
    }
    return rv;
}

// 使用 Openssl 建立 https 通讯
int SF_MutualTLS() {
    SSL_CTX *sslCtx = NULL;
    BIO  *bio = NULL;
    SSL  *ssl = NULL;
    X509 *x509 = NULL;
    SSL_library_init();
    
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    char buffer[1024] = {0};
    
    int ret = CY_GetSSLContext(
            hAppHandle,
            pucSSLContainerName,
            uiSSLContainerNameLen,
            pucPinInfo,
            uiPinInfoLen,
            (void **) &sslCtx);
    if (ret != CY_R_SUCCESS) {
        printf("CY_GetSSLContext error: error code %02x\n", ret);
        goto cleanup;
    }
    if (sslCtx==NULL) {
        printf("CY_GetSSLContext error:");
        goto cleanup;
    }
    bio = BIO_new_ssl_connect(sslCtx);
    if (bio == NULL) {
        printf("无法创建 BIO 对象\n");
        goto cleanup;
    }
    BIO_get_ssl(bio, NULL);

    BIO_set_conn_hostname(bio, "10.13.75.131");
    BIO_set_conn_port(bio, "1440");

    BIO_get_ssl(bio, &ssl);

    const char *pcMessage = "Hello World\n";
    if (SSL_connect(ssl) <= 0) {
        printf("SSL_connect error.\n");
        ERR_print_errors_fp(stdout);
        goto cleanup;
    } else {
        printf("SSL_connect success.\n");
    }
    ret = (int)SSL_get_verify_result(ssl);
    if (ret != X509_V_OK) {
        printf("SSL_get_verify_result: %d\n", ret);
        goto cleanup;
    } else {
        printf("Certificate verification success\n");
    }

    ret = BIO_write(bio, pcMessage, (int) strlen(pcMessage));
    printf("Bio write: %d\n", ret);
    do {
        ret = BIO_read(bio, buffer, 1024);
        for (int i = 0; i < ret; ++i) {
            printf("%02x", buffer[i]);
        }
    } while (ret > 0 || BIO_should_retry(bio));
cleanup:
    if(x509) X509_free(x509);
    if(bio) BIO_free_all(bio);
    if(sslCtx) SSL_CTX_free(sslCtx);
    return 0;
}

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    // 初始化服务
    int rv = CY_InitService(&hAppHandle, pGlbAppFilePath);
    if (rv != CY_R_SUCCESS) {
        printf("CY_InitService error, error code: %02x\n", rv);
    } else {
        printf("CY_InitService success.\n");
    }

    // 证书管理
    rv = SF_CertificateManagement();
    if (rv != CY_R_SUCCESS) {
        printf("SF_CertificateManagement error, error code: %02x\n", rv);
    } else {
        printf("SF_CertificateManagement success.\n");
    }

    // 密码运算
    rv = SF_CryptographicOperation();
    if (rv != CY_R_SUCCESS) {
        printf("SF_CryptographicOperation error, error code: %02x\n", rv);
    } else {
        printf("SF_CryptographicOperation success.\n");
    }
    
    // 双向 TLS
    SF_MutualTLS();

    // 关闭，释放 Handle
    CY_Finalize(hAppHandle);
    hAppHandle = NULL;
}




// //
// // Create by kong
// // Copyright 2025 China Automotive Research Software Evaluating Co., Ltd.
// //

// #include <stdio.h>
// #include <string.h>
// #include <openssl/ssl.h>
// #include <openssl/err.h>

// #include "cyber_pki.h"
// #include "cyber_error.h"
// #include "cyber_tls.h"

// static void *hAppHandle = NULL;

// // 文件存储路径
// static char *pGlbAppFilePath = "./cyber";

// // 用户容器名及 PIN 码
// static unsigned char pucCyberContainerName[] = "cyber";
// static unsigned int uiCyberContainerNameLen = 5;
// static unsigned char pucSSLContainerName[] = "ssl";
// static unsigned int uiSSLContainerNameLen = 3;
// static unsigned char pucPinInfo[] = "12345678";
// static unsigned int uiPinInfoLen = 8;

// // 16 进制打印
// void hex_print(const unsigned char *val, unsigned int len) {
//     if (val == NULL) { return; }
//     if (len == 0)    { return; }
//     for (int i = 0; i < len; ++i) {
//         printf("%02x", val[i]);
//     }
//     printf("\n");
// }

// // 读取文件
// int read_file(const char *file_path, unsigned char **file_content, unsigned int *file_length) {
//     FILE *file = fopen(file_path, "rb");
//     if (!file) {
//         perror("Failed to open file");
//         return -1;
//     }
//     fseek(file, 0, SEEK_END);
//     *file_length = ftell(file);
//     fseek(file, 0, SEEK_SET);
//     *file_content = (unsigned char *)malloc(*file_length + 1);
//     if (!*file_content) {
//         perror("Failed to allocate memory");
//         fclose(file);
//         return -1;
//     }
//     size_t bytes_read = fread(*file_content, 1, *file_length, file);
//     if (bytes_read != *file_length) {
//         free(*file_content);
//         fclose(file);
//         return -1;
//     }
//     (*file_content)[*file_length] = '\0';
//     fclose(file);
//     return 0;
// }

// // 证书管理
// int SF_CertificateManagement() {

//     // 证书链
//     unsigned char *pucBuffer = NULL;
//     unsigned int uiBufferLen = 0;
//     // 获取证书链
//     read_file("../../examples/Assets/cert_chain.pem", &pucBuffer, &uiBufferLen);
//     // 导入证书链
//     int rv = CY_ImportTrustedCertificateChain(hAppHandle, pucBuffer, uiBufferLen);
//     if (pucBuffer) free(pucBuffer);
//     if (rv != CY_R_SUCCESS) {
//         printf("CY_ImportTrustedCertificateChain error, error code: %02x\n", rv);
//         return rv;
//     } else {
//         printf("CY_ImportTrustedCertificateChain success\n");
//     }
//     // 判断用户证书是否存在
//     rv = CY_GetCertificateStatus(
//             hAppHandle,
//             pucCyberContainerName,
//             uiCyberContainerNameLen,
//             pucPinInfo,
//             uiPinInfoLen);
//     if (rv != CY_R_SUCCESS) {
//         // 生成 SM2 密钥对
//         rv = CY_GenEccKeyPair(
//                 hAppHandle,
//                 pucCyberContainerName,
//                 uiCyberContainerNameLen,
//                 pucPinInfo,
//                 uiPinInfoLen,
//                 SGD_SM2,
//                 SGD_KEYUSAGE_SIGN,
//                 0);
//         if (rv != CY_R_SUCCESS) {
//             printf("CY_GenEccKeyPair error, error code: %02x\n", rv);
//             return rv;
//         } else {
//             printf("CY_GenEccKeyPair success\n");
//         }
//         SGD_NAME_INFO nameInfo = {0};
//         strcpy(nameInfo.dn_c,  "CN");
//         strcpy(nameInfo.dn_s,  "Tianjin");
//         strcpy(nameInfo.dn_l,  "Tianjin");
//         strcpy(nameInfo.dn_o,  "Catarc");
//         strcpy(nameInfo.dn_sn, "Catarc");
//         strcpy(nameInfo.dn_cn, "Security");
//         pucBuffer = malloc(2048);
//         if (pucBuffer) {
//             memset(pucBuffer, 0x00, 2048);
//         }
//         rv = CY_GenerateCertificateSigningRequest(
//                 hAppHandle,
//                 pucCyberContainerName,
//                 uiCyberContainerNameLen,
//                 pucPinInfo,
//                 uiPinInfoLen,
//                 &nameInfo,
//                 pucBuffer,
//                 &uiBufferLen);
//         if (rv != CY_R_SUCCESS) {
//             printf("CY_GenerateCertificateSigningRequest error, error code: %02x\n", rv);
//             return rv;
//         } else {
//             printf("CY_GenerateCertificateSigningRequest success.\n");
//             hex_print(pucBuffer, uiBufferLen);
//         }
//         if (pucBuffer) {
//             free(pucBuffer);
//             pucBuffer = NULL;
//         }
//     }
//     // 导入签名密钥及签名证书
//     read_file("../../examples/Assets/sign_cert.pem", &pucBuffer, &uiBufferLen);
//     rv = CY_ImportCertificate(
//             hAppHandle,
//             pucSSLContainerName,
//             uiSSLContainerNameLen,
//             SGD_KEYUSAGE_SIGN,
//             pucBuffer,
//             uiBufferLen);
//     if (pucBuffer) free(pucBuffer);
//     pucBuffer = NULL;
//     if (rv != CY_R_SUCCESS) {
//         printf("CY_ImportSignCertificate error, error code: %02x\n", rv);
//         return rv;
//     } else {
//         printf("CY_ImportSignCertificate success\n");
//     }
//     read_file("../../examples/Assets/sign_key.der", &pucBuffer, &uiBufferLen);
//     rv = CY_ImportEccKeyPair(
//             hAppHandle,
//             pucSSLContainerName,
//             uiSSLContainerNameLen,
//             pucPinInfo,
//             uiPinInfoLen,
//             SGD_SM2,
//             SGD_KEYUSAGE_SIGN,
//             pucBuffer,
//             uiBufferLen);
//     if (pucBuffer) free(pucBuffer);
//     pucBuffer = NULL;
//     if (rv != CY_R_SUCCESS) {
//         printf("CY_ImportSignEccKeyPair error, error code: %02x\n", rv);
//         return rv;
//     } else {
//         printf("CY_ImportSignEccKeyPair success\n");
//     }
//     // 导入加密密钥及加密证书
//     read_file("../../examples/Assets/enc_cert.pem", &pucBuffer, &uiBufferLen);
//     rv = CY_ImportCertificate(
//             hAppHandle,
//             pucSSLContainerName,
//             uiSSLContainerNameLen,
//             SGD_KEYUSAGE_ENC,
//             pucBuffer,
//             uiBufferLen);
//     if (pucBuffer) free(pucBuffer);
//     pucBuffer = NULL;
//     if (rv != CY_R_SUCCESS) {
//         printf("CY_ImportEncCertificate error, error code: %02x\n", rv);
//         return rv;
//     } else {
//         printf("CY_ImportEncCertificate success\n");
//     }
//     read_file("../../examples/Assets/enc_key.der", &pucBuffer, &uiBufferLen);
//     rv = CY_ImportEccKeyPair(
//             hAppHandle,
//             pucSSLContainerName,
//             uiSSLContainerNameLen,
//             pucPinInfo,
//             uiPinInfoLen,
//             SGD_SM2,
//             SGD_KEYUSAGE_ENC,
//             pucBuffer,
//             uiBufferLen);
//     if (pucBuffer) free(pucBuffer);
//     pucBuffer = NULL;
//     if (rv != CY_R_SUCCESS) {
//         printf("CY_ImportEncEccKeyPair error, error code: %02x\n", rv);
//         return rv;
//     } else {
//         printf("CY_ImportEncEccKeyPair success\n");
//     }

//     pucBuffer = (unsigned char *)malloc(1024);
//     uiBufferLen = 1024;
//     rv = CY_ExportCertificate(
//             hAppHandle,
//             pucSSLContainerName,
//             uiSSLContainerNameLen,
//             SGD_KEYUSAGE_SIGN,
//             pucBuffer,
//             &uiBufferLen);
//     if (rv != CY_R_SUCCESS) {
//         printf("CY_ExportSignCertificate error, error code: %02x\n", rv);
//         return rv;
//     } else {
//         printf("CY_ExportSignCertificate success\n");
//         hex_print(pucBuffer, uiBufferLen);
//     }
//     free(pucBuffer);
//     pucBuffer = NULL;

//     pucBuffer = (unsigned char *)malloc(1024);
//     uiBufferLen = 1024;
//     rv = CY_ExportCertificate(
//             hAppHandle,
//             pucSSLContainerName,
//             uiSSLContainerNameLen,
//             SGD_KEYUSAGE_ENC,
//             pucBuffer,
//             &uiBufferLen);
//     if (rv != CY_R_SUCCESS) {
//         printf("CY_ExportSignCertificate error, error code: %02x\n", rv);
//         return rv;
//     } else {
//         printf("CY_ExportSignCertificate success\n");
//         hex_print(pucBuffer, uiBufferLen);
//     }
//     if (pucBuffer) {
//         free(pucBuffer);
//     }
//     return rv;
// }

// int SF_CryptographicOperation() {
//     int rv;
//     // 对称解密
//     unsigned char ucKeyData[16] = {
//             0xC0, 0x1F, 0x29, 0x8C, 0x6C, 0x9B, 0x8D, 0x9D,
//             0x5A, 0xDC, 0x60, 0x35, 0xFC, 0xC7, 0xC6, 0x61 };
//     unsigned int uiKeyDataLen = 16;

//     unsigned char ucIvData[16] = {
//             0x98, 0x1E, 0x1E, 0x99, 0x1F, 0xC1, 0xCF, 0x92,
//             0x15, 0x3C, 0x63, 0x9B, 0x75, 0x24, 0x18, 0xA8 };
//     unsigned int uiIvDataLen = 16;
//     void *hSymmKeyObj = NULL;
//     rv = CY_CreateSymmKeyObj(
//             &hSymmKeyObj,
//             ucKeyData,
//             uiKeyDataLen,
//             ucIvData,
//             uiIvDataLen,
//             SGD_DEC,
//             SGD_AES_OFB);
//     if (rv != CY_R_SUCCESS) {
//         printf("CY_CreateSymmKeyObj fail, fail code: %02x\n", rv);
//         return rv;
//     } else {
//         printf("CY_CreateSymmKeyObj success\n");
//     }
//     unsigned char ucCipherData[] = {
//             0x74, 0xa1, 0x4a, 0x13, 0x07, 0xfa, 0x6a, 0x83, 0xcb, 0xd8, 0x2e,
//             0x98, 0x47, 0xda, 0xdd, 0xe7, 0x97, 0xe8, 0xd5, 0x33, 0x4d, 0x1e,
//             0x1d, 0x6f, 0x0c, 0x7d, 0xae, 0x12, 0xef, 0xec, 0xf4, 0x3e, 0xcd,
//             0x41, 0x8e, 0x32 };
//     unsigned int uiCipherDataLen = sizeof(ucCipherData);
//     unsigned char ucOutData[1024] = {0};
//     unsigned int uiOutDataLen = 1024;
//     rv = CY_SymmDecryptUpdate(hSymmKeyObj, ucCipherData, uiCipherDataLen, ucOutData, &uiOutDataLen);
//     printf("CY_SymmDecryptUpdate: %d\n", rv);
//     hex_print(ucOutData, uiOutDataLen);

//     rv = CY_SymmDecryptFinal(hSymmKeyObj, ucOutData, &uiOutDataLen);
//     printf("CY_SymmDecryptFinal: %d\n", rv);
//     hex_print(ucOutData, uiOutDataLen);

//     rv = CY_DestroySymmKeyObj(hSymmKeyObj);
//     printf("CY_DestroySymmKeyObj: %d\n", rv);

//     // 非对称签名验签
//     unsigned char ucPublicKey[1024] = {0};
//     unsigned int uiPublicKeyLen = 1024;
//     rv = CY_GetEccPublicKey(
//             hAppHandle,
//             pucCyberContainerName,
//             uiCyberContainerNameLen,
//             SGD_KEYUSAGE_SIGN,
//             ucPublicKey,
//             &uiPublicKeyLen);
//     if (rv != CY_R_SUCCESS) {
//         printf("CY_GetEccPublicKey fail, fail code: %02x\n", rv);
//         return rv;
//     } else {
//         printf("CY_GetEccPublicKey success\n");
//         hex_print(ucPublicKey, uiPublicKeyLen);
//     }

//     unsigned char ucSignature[1024] = {0};
//     unsigned int uiSignatureLen = sizeof(ucSignature);
//     unsigned char ucInData[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
//     unsigned int  uiInDataLen = sizeof(ucInData);
//     rv = CY_EccSign(
//             hAppHandle,
//             pucCyberContainerName,
//             uiCyberContainerNameLen,
//             pucPinInfo,
//             uiPinInfoLen,
//             SGD_SM3,
//             ucInData,
//             uiInDataLen,
//             ucSignature,
//             &uiSignatureLen);
//     if (rv != CY_R_SUCCESS) {
//         printf("CY_EccSign fail, fail code: %02x\n", rv);
//     } else {
//         printf("CY_EccSign success\n");
//         hex_print(ucSignature, uiSignatureLen);
//     }
//     rv = CY_EccVerifySign(
//             SGD_SM3,
//             ucPublicKey,
//             uiPublicKeyLen,
//             ucInData,
//             uiInDataLen,
//             ucSignature,
//             uiSignatureLen);
//     if (rv != CY_R_SUCCESS) {
//         printf("CY_EccVerifySign fail, fail code: %02x\n", rv);
//         return rv;
//     } else {
//         printf("CY_EccVerifySign success\n");
//     }
//     memset(ucOutData, 0x00, 1024);
//     uiOutDataLen = 1024;

//     // 非对称加密解密
//     rv = CY_EccEncrypt(
//             ucPublicKey,
//             uiPublicKeyLen,
//             ucInData,
//             uiInDataLen,
//             ucOutData,
//             &uiOutDataLen);
//     if (rv != CY_R_SUCCESS) {
//         printf("CY_EccEncrypt fail, fail code: %02x\n", rv);
//         return rv;
//     } else {
//         printf("CY_EccEncrypt success\n");
//         hex_print(ucOutData, uiOutDataLen);
//     }

//     unsigned char ucPlainData[1024] = {0};
//     unsigned int uiPlainDataLen = sizeof(ucPlainData);
//     rv = CY_EccDecrypt(
//             hAppHandle,
//             pucCyberContainerName,
//             uiCyberContainerNameLen,
//             pucPinInfo,
//             uiPinInfoLen,
//             ucOutData,
//             uiOutDataLen,
//             ucPlainData,
//             &uiPlainDataLen);
//     if (rv != CY_R_SUCCESS) {
//         printf("CY_EccDecrypt fail, fail code: %02x\n", rv);
//         return rv;
//     } else {
//         printf("CY_EccDecrypt success\n");
//         hex_print(ucPlainData, uiPlainDataLen);
//     }
//     return rv;
// }

// // 使用 Openssl 建立 https 通讯
// int SF_MutualTLS() {
//     SSL_CTX *sslCtx = NULL;
//     BIO  *bio = NULL;
//     SSL  *ssl = NULL;
//     X509 *x509 = NULL;
//     SSL_library_init();
//     OpenSSL_add_all_algorithms();
//     SSL_load_error_strings();
//     char buffer[1024] = {0};
//     int ret = CY_GetSSLContext(
//             hAppHandle,
//             pucSSLContainerName,
//             uiSSLContainerNameLen,
//             pucPinInfo,
//             uiPinInfoLen,
//             (void **) &sslCtx);
//     if (ret != CY_R_SUCCESS) {
//         printf("CY_GetSSLContext error: error code %02x\n", ret);
//         goto cleanup;
//     }
//     bio = BIO_new_ssl_connect(sslCtx);
//     BIO_get_ssl(bio, NULL);

//     BIO_set_conn_hostname(bio, "127.0.0.1");
//     BIO_set_conn_port(bio, "4433");

//     BIO_get_ssl(bio, &ssl);

//     const char *pcMessage = "Hello World\n";
//     if (SSL_connect(ssl) <= 0) {
//         printf("SSL_connect error.\n");
//         ERR_print_errors_fp(stdout);
//         goto cleanup;
//     } else {
//         printf("SSL_connect success.\n");
//     }
//     ret = (int)SSL_get_verify_result(ssl);
//     if (ret != X509_V_OK) {
//         printf("SSL_get_verify_result: %d\n", ret);
//         goto cleanup;
//     } else {
//         printf("Certificate verification success\n");
//     }

//     ret = BIO_write(bio, pcMessage, (int) strlen(pcMessage));
//     printf("Bio write: %d\n", ret);
//     do {
//         ret = BIO_read(bio, buffer, 1024);
//         for (int i = 0; i < ret; ++i) {
//             printf("%02x", buffer[i]);
//         }
//     } while (ret > 0 || BIO_should_retry(bio));
// cleanup:
//     X509_free(x509);
//     BIO_free_all(bio);
//     SSL_CTX_free(sslCtx);
//     return 0;
// }

// int main(int argc, char** argv) {
//     (void)argc;
//     (void)argv;

//     // 初始化服务
//     int rv = CY_InitService(&hAppHandle, pGlbAppFilePath);
//     if (rv != CY_R_SUCCESS) {
//         printf("CY_InitService error, error code: %02x\n", rv);
//     } else {
//         printf("CY_InitService success.\n");
//     }

//     // 证书管理
//     rv = SF_CertificateManagement();
//     if (rv != CY_R_SUCCESS) {
//         printf("SF_CertificateManagement error, error code: %02x\n", rv);
//     } else {
//         printf("SF_CertificateManagement success.\n");
//     }

//     // 密码运算
//     rv = SF_CryptographicOperation();
//     if (rv != CY_R_SUCCESS) {
//         printf("SF_CryptographicOperation error, error code: %02x\n", rv);
//     } else {
//         printf("SF_CryptographicOperation success.\n");
//     }

//     // 双向 TLS
//     SF_MutualTLS();

//     // 关闭，释放 Handle
//     CY_Finalize(hAppHandle);
//     hAppHandle = NULL;
// }