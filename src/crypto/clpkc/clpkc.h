#ifndef __CLPKC_H__
#define __CLPKC_H__

#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define USE_FIX_DATA    1
#define VERBOSE_LEVEL   6
#define DEBUG_LEVEL     5
#define INFO_LEVEL      4
#define WARNING_LEVEL   3
#define ERROR_LEVEL     2
#define FATAL_LEVEL     1
#define NO_DEBUG        0



void trace_info(const int level,const char* file, const char* func, int line, const char* format,...);

#define filename(x) strrchr(x,'/')?strrchr(x,'/')+1:x

//#define MC_LOG_DEBUG(...) trace_info(DEBUG_LEVEL, filename(__FILE__), __FUNCTION__, __LINE__, __VA_ARGS__)
//#define MC_LOG_INFO(...)  trace_info(INFO_LEVEL, filename(__FILE__), __FUNCTION__, __LINE__, __VA_ARGS__)
//#define MC_LOG_WARN(...)  trace_info(WARNING_LEVEL, filename(__FILE__), __FUNCTION__, __LINE__, __VA_ARGS__)
//#define MC_LOG_ERR(...)   trace_info(ERROR_LEVEL, filename(__FILE__), __FUNCTION__, __LINE__, __VA_ARGS__)
#define MC_LOG_DEBUG(...)
#define MC_LOG_INFO(...)
#define MC_LOG_WARN(...)
#define MC_LOG_ERR(...)
void cy_hex_dump(char *s, unsigned char *p, int size);


int GenCLPKCMasterKey(unsigned char *MasterPrivateKey,int *MasterPrivateKeyLen, unsigned char *MasterPublicKey, int *MasterPublicKeyLen);
int GenUAINFO(unsigned char *dPreA, int *dPreALen, unsigned char *UA, int *UALen);
int CalHAINFO(unsigned char *UserId, int UserIdLen, unsigned char *pubKey, int pubKeyLen, unsigned char *HA, int *HALen);

int CalWAInfo(unsigned char *UA, int UA_len, unsigned char *WA, int *WA_len, unsigned char *wb, int *wLen);

int CalLamdaInfo(unsigned char *WA, int WA_len, unsigned char *HA, int HALen, unsigned char *lamada, int *lamda_len);
int CaltAInfo(unsigned char *w, int wLen, unsigned char *lamada, int lamadaLen, unsigned char *ms, int msLen, unsigned char *tA, int *tALen);
int CalPAInfo(unsigned char *WA, int WA_len, unsigned char *lamda, int lamda_len, unsigned char *MasterPublicKey, int MasterPublicKeyLen, unsigned char *PA, int *PALen);

int CalprePAInfo(unsigned char *dA, int dALen, unsigned char *PA, int *PALen);
int CaldAValue(unsigned char *tA, int tALen, unsigned char *dPreA, int dPreALen, unsigned char *dA, int *dALen);
int CLPKC_Sign(unsigned char *message, int messageLen, unsigned char *HA, int HALen, unsigned char *WA, int WA_len, unsigned char *dA, int dALen, unsigned char *Signature, int *SignatureLen);
int CLPKC_Verify(unsigned char *PA, int PALen, unsigned char *message, int messageLen, unsigned char *HA, int HALen, unsigned char *WA, int WA_len, unsigned char *Signature, int SignatureLen);
int CLPKC_Encrypt(unsigned char *PA, int PALen, unsigned char *message, int messageLen, unsigned char *Ciphertext,  int *CiphertextLen);
int CLPKC_Decrypt(unsigned char *dA, int dALen, unsigned char *Ciphertext, int CiphertextLen, unsigned char *message, int *messageLen);






#ifdef  __cplusplus
}
#endif

#endif