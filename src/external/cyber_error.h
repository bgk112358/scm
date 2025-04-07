//
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//

#ifndef SCM_CYBER_ERROR_H
#define SCM_CYBER_ERROR_H

/* Reason codes. */
#define CYBER_R_SUCCESS                0x00000000
#define CYBER_R_ERR                    0x00000001

#define CYBER_R_ERR_APP                0x10000001
#define CYBER_R_ERR_INPUT              0x10000002
#define CYBER_R_ERR_MEMORY             0x10000003
#define CYBER_R_ERR_BUFFER_TOO_SMALL   0x10000004
#define CYBER_R_ERR_NOT_INIT           0x10000005
#define CYBER_R_ERR_CRED               0x10000006
#define CYBER_R_ERR_PIN                0x10000007
#define CYBER_R_ERR_UNSUPPORT_FUNCTION 0x10000008

#define CYBER_R_ERR_FILE_MEMORY        0x20000001
#define CYBER_R_ERR_FILE_INVALID       0x20000002
#define CYBER_R_ERR_FILE_OPEN          0x20000003
#define CYBER_R_ERR_FILE_SIZE          0x20000004
#define CYBER_R_ERR_FILE_WRITE         0x20000005
#define CYBER_R_ERR_FILE_READ          0x20000006
#define CYBER_R_ERR_FILE_NOT_FOUND     0x20000007
#define CYBER_R_ERR_FILE_PATH          0x20000008
#define CYBER_R_ERR_CONTAINER_CREATE   0x20000009
#define CYBER_R_ERR_CONTAINER_WRITE    0x2000000a
#define CYBER_R_ERR_CONTAINER_READ     0x2000000b

#define CYBER_R_ERR_KEY_GEN            0x30000000
#define CYBER_R_ERR_CTX_NOT_INIT       0x30000001
#define CYBER_R_ERR_UNSUPPORT_ALG      0x30000002
#define CYBER_R_ERR_UNSUPPORT_FORMAT   0x30000003
#define CYBER_R_ERR_UNSUPPORT          0x30000004
#define CYBER_R_ERR_ENCRYPT            0x30000005
#define CYBER_R_ERR_DECRYPT            0x30000006
#define CYBER_R_ERR_COMPUTE            0x30000007
#define CYBER_R_ERR_SIGN               0x30000008
#define CYBER_R_ERR_VFY_SIGN           0x30000009
#define CYBER_R_ERR_KEY_NOT_FOUND      0x3000000a
#define CYBER_R_ERR_DH_KEY             0x3000000b
#define CYBER_R_ERR_DH_COMPUTE         0x3000000c

#define CYBER_R_ERR_CERT               0x40000001
#define CYBER_R_ERR_CERT_FORMAT        0x40000002
#define CYBER_R_ERR_CERT_TIME          0x40000003
#define CYBER_R_ERR_CERT_GET_INFO      0x40000004
#define CYBER_R_ERR_CERT_NOT_FOUND     0x40000005
#define CYBER_R_ERR_CERT_CHAIN_NOT_FOUND   0x40000005
#define CYBER_R_ERR_CERT_VFY           0x40000006
#define CYBER_R_CSR_GEN                0x40000007

#define CYBER_R_ERR_NET_INIT           0x50000001
#define CYBER_R_ERR_NET                0x50000002
#define CYBER_R_ERR_NET_REQUEST        0x50000003
#define CYBER_R_ERR_NET_DATA_FORMAT    0x50000004
#define CYBER_R_ERR_NET_RESPONSE       0x50000005
#define CYBER_R_ERR_NET_HEADER         0x50000006
#define CYBER_R_ERR_SSL_CERT           0x50000007
#define CYBER_R_ERR_SSL                0x50000008

#define CYBER_R_ERR_DRIVER_INIT        0x60000001
#define CYBER_R_ERR_DRIVER_LOGIN       0x60000002
#define CYBER_R_ERR_DRIVER_NOT_FOUND   0x60000003

#endif //SCM_CYBER_ERROR_H