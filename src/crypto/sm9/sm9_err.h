#ifndef __SM9_ERR_H__
#define __SM9_ERR_H__

# define ERR_LIB_SM9             61
# define ERR_R_SM9_LIB  ERR_LIB_SM9/* 61 */

# define SM9err(f,r) ERR_PUT_error(ERR_LIB_SM9,(f),(r),OPENSSL_FILE,OPENSSL_LINE)


#define LOG_SM9_STUB() printf("%s : %d\n", __FUNCTION__, __LINE__) /* LOG_SM9_STUB() */

#endif /* __SM9_ERR_H__ */
