#ifndef __SM9_OBJ_MAC_H__
#define __SM9_OBJ_MAC_H__



#define SN_id_sm9PublicKey              "id-sm9PublicKey"
#define NID_id_sm9PublicKey             1168
#define OBJ_id_sm9PublicKey             OBJ_sm_scheme,302L

#define SN_sm9sign              "sm9sign"
#define NID_sm9sign             1210//1259//1169
#define OBJ_sm9sign             OBJ_sm_scheme,302L,1L

#define SN_sm9keyagreement              "sm9keyagreement"
#define NID_sm9keyagreement             1170
#define OBJ_sm9keyagreement             OBJ_sm_scheme,302L,2L

#define SN_sm9encrypt           "sm9encrypt"
#define NID_sm9encrypt          1211//1260//1171
#define OBJ_sm9encrypt          OBJ_sm_scheme,302L,3L

#define SN_sm9hash1             "sm9hash1"
#define NID_sm9hash1            1172
#define OBJ_sm9hash1            OBJ_sm_scheme,302L,4L

#define SN_sm9hash2             "sm9hash2"
#define NID_sm9hash2            1209
#define OBJ_sm9hash2            OBJ_sm_scheme,303L,7L

#define SN_sm9kdf               "sm9kdf"
#define NID_sm9kdf              1173
#define OBJ_sm9kdf              OBJ_sm_scheme,302L,5L

#define SN_id_sm9MasterSecret           "id-sm9MasterSecret"
#define NID_id_sm9MasterSecret          1174
#define OBJ_id_sm9MasterSecret          OBJ_sm_scheme,302L,6L

#define SN_sm9bn256v1           "sm9bn256v1"
#define NID_sm9bn256v1          1209//1258//1175
#define OBJ_sm9bn256v1          OBJ_sm_scheme,302L,6L,1L

#define SN_sm9sign_with_sm3             "sm9sign-with-sm3"
#define NID_sm9sign_with_sm3            1176
#define OBJ_sm9sign_with_sm3            OBJ_sm9sign,1L

#define SN_sm9sign_with_sha256          "sm9sign-with-sha256"
#define NID_sm9sign_with_sha256         1177
#define OBJ_sm9sign_with_sha256         OBJ_sm9sign,2L

#define SN_sm9encrypt_with_sm3_xor              "sm9encrypt-with-sm3-xor"
#define NID_sm9encrypt_with_sm3_xor             1213//1262//1178
#define OBJ_sm9encrypt_with_sm3_xor             OBJ_sm9encrypt,1L

#define SN_sm9encrypt_with_sm3_sms4_cbc         "sm9encrypt-with-sm3-sms4-cbc"
#define NID_sm9encrypt_with_sm3_sms4_cbc                1179
#define OBJ_sm9encrypt_with_sm3_sms4_cbc                OBJ_sm9encrypt,2L

#define SN_sm9encrypt_with_sm3_sms4_ctr         "sm9encrypt-with-sm3-sms4-ctr"
#define NID_sm9encrypt_with_sm3_sms4_ctr                1180
#define OBJ_sm9encrypt_with_sm3_sms4_ctr                OBJ_sm9encrypt,3L

#define SN_sm9hash1_with_sm3            "sm9hash1-with-sm3"
#define NID_sm9hash1_with_sm3           1212//1261//1181
#define OBJ_sm9hash1_with_sm3           OBJ_sm9hash1,1L

#define SN_sm9hash1_with_sha256         "sm9hash1-with-sha256"
#define NID_sm9hash1_with_sha256                1182
#define OBJ_sm9hash1_with_sha256                OBJ_sm9hash1,2L

#define SN_sm9hash2_with_sm3            "sm9hash2-with-sm3"
#define NID_sm9hash2_with_sm3           1210
#define OBJ_sm9hash2_with_sm3           OBJ_sm9hash2,1L

#define SN_sm9hash2_with_sha256         "sm9hash2-with-sha256"
#define NID_sm9hash2_with_sha256                1211
#define OBJ_sm9hash2_with_sha256                OBJ_sm9hash2,2L

#define SN_sm9kdf_with_sm3              "sm9kdf-with-sm3"
#define NID_sm9kdf_with_sm3             1214//1263//1183
#define OBJ_sm9kdf_with_sm3             OBJ_sm9kdf,1L

#define SN_sm9kdf_with_sha256           "sm9kdf-with-sha256"
#define NID_sm9kdf_with_sha256          1184
#define OBJ_sm9kdf_with_sha256          OBJ_sm9kdf,2L




#define SN_kx_sm9               "KxSM9"
#define LN_kx_sm9               "kx-sm9"
#define NID_kx_sm9              1196

#define SN_kx_sm9dhe            "KxSM9DHE"
#define LN_kx_sm9dhe            "kx-sm9dhe"
#define NID_kx_sm9dhe           1197

#define SN_auth_sm2             "AuthSM2"
#define LN_auth_sm2             "auth-sm2"
//#define NID_auth_sm2            1198

#define SN_auth_sm9             "AuthSM9"
#define LN_auth_sm9             "auth-sm9"
#define NID_auth_sm9            1199


# define EVP_PKEY_SM9_MASTER NID_id_sm9MasterSecret
# define EVP_PKEY_SM9        NID_id_sm9PublicKey


#endif 