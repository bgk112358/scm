//
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//

#ifndef SCM_cyber_ERROR_H
#define SCM_cyber_ERROR_H

/* Reason codes. */
#define CY_R_SUCCESS                      0x00000000
#define CY_R_UNKNOWN_ERR                  0x02000001
#define CY_R_NOT_SUPPORT_YET_ERR          0x02000002
#define CY_R_FILE_ERR                     0x02000003
#define CY_R_PROVIDER_TYPE_ERR            0x02000004
#define CY_R_LOAD_PROVIDER_ERR            0x02000005
#define CY_R_LOAD_DEVMNG_API_ERR          0x02000006
#define CY_R_ALGO_TYPE_ERR                0x02000007
#define CY_R_NAME_LEN_ERR                 0x02000008
#define CY_R_KEY_USAGE_ERR                0x02000009
#define CY_R_MODULUS_LEN_ERR              0x02000010
#define CY_R_NOT_INITIALIZE_ERR           0x02000011
#define CY_R_OBJ_ERR                      0x02000012
#define CY_R_FILE_NOTFOUND_ERR            0x02000013
#define CY_R_MEMORY_ERR                   0x02000100
#define CY_R_TIMEOUT_ERR                  0x02000101
#define CY_R_CONNECT_ERR                  0x02000102
#define CY_R_RESOLVE_HOST_ERR             0x02000103
#define CY_R_INDATA_LEN_ERR               0x02000200
#define CY_R_INDATA_ERR                   0x02000201
#define CY_R_GEN_RAND_ERR                 0x02000300
#define CY_R_HASH_OBJ_ERR                 0x02000301
#define CY_R_HASH_ERR                     0x02000302
#define CY_R_GENKEY_ERR                   0x02000303
#define CY_R_RSA_MODULUS_LEN_ERR          0x02000304
#define CY_R_ENC_ERR                      0x02000306
#define CY_R_DEC_ERR                      0x02000307
#define CY_R_HASH_NOTEQUAL_ERR            0x02000308
#define CY_R_KEY_NOTFOUND_ERR             0x02000309
#define CY_R_CERT_NOTFOUND_ERR            0x02000310
#define CY_R_NOT_EXPORT_ERR               0x02000311
#define CY_R_CERT_REVOKED_ERR             0x02000316
#define CY_R_CERT_NOT_YET_VALID_ERR       0x02000317
#define CY_R_CERT_HAS_EXPIRED_ERR         0x02000318
#define CY_R_CERT_VERIFY_ERR              0x02000319
#define CY_R_CERT_ENCODE_ERR              0x02000320
#define CY_R_GEN_CERT_ERR                 0x02000321
#define CY_R_GET_CERTINFO_ERR             0x02000322
#define CY_R_CERT_PUBLICKEY_NOTMATCH_ERR  0x02000323
#define CY_R_DECRYPT_PAD_ERR              0x02000400
#define CY_R_MAC_LEN_ERR                  0x02000401
#define CY_R_KEY_INFO_TYPE_ERR            0x02000402
#define CY_R_NOT_LOGIN                    0x02000403
#define CY_R_KEY                          0x02000404
#define CY_R_KEY_ENCODE_ERR               0x02000405
#define CY_R_SIGN_ERR                     0x02000406
#define CY_R_VERIFY_ERR                   0x02000407
#define CY_R_PKCS7_ENCODE_ERR             0x02000408
#define CY_R_SCEP_STATUS_ERR              0x02000409
#define CY_R_SCEP_ATTRIBUTE_VERIFY_ERR    0x0200040A
#define CY_R_SCEP_MESSAGE_VERIFY_ERR      0x0200040B

#endif //SCM_cyber_ERROR_H