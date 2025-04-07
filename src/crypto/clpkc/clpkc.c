#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <stdarg.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "clpkc.h"

#include <stdio.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <openssl/bn.h>

int g_nIwallLogLevel = INFO_LEVEL;//DEBUG_LEVEL;


int cy_openssl_version()
{
    printf("OpenSSL version: %s\n", SSLeay_version(SSLEAY_VERSION));
  // 打印 OpenSSL 版本号
  printf("OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);

  // 打印更详细的版本信息
  printf("OpenSSL version (full): %s\n", OpenSSL_version(OPENSSL_VERSION));

  // 打印构建日期
  printf("Build date: %s\n", OpenSSL_version(OPENSSL_BUILT_ON));

  // 打印平台信息
  printf("Platform: %s\n", OpenSSL_version(OPENSSL_PLATFORM));
 
    return 0;
}

void cy_hex_dump(char *s, unsigned char *p, int size)
{
   const uint8_t *c = p;
    assert(p);
    
    printf("Dumping %s %u bytes from %p:\n", s,size, p);
 
    while (size > 0) {
        unsigned i;
 
        for (i = 0; i < 16; i++) {
            if (i < size)
                printf("%02x ", c[i]);
            else
                printf("   ");
        }
 
        for (i = 0; i < 16; i++) {
            if (i < size)
                printf("%c", c[i] >= 32 && c[i] < 127 ? c[i] : '.');
            else
                printf(" ");
        }
 
        printf("\n");
 
        c += 16;
 
        if (size <= 16)
            break;
 
        size -= 16;
    }
}

void trace_info(const int level,const char* file, const char* func, int line, const char* format,...)
{
    if(g_nIwallLogLevel < level)
    {
        return;
    }
   char szDate[128] = {0};
   time_t timer;
   struct tm *tf = NULL;

   timer = time(NULL);
   tf = localtime(&timer);
   sprintf(szDate, "[%04d-%02d-%02d %02d:%02d:%02d] ",
       tf->tm_year + 1900, tf->tm_mon + 1, tf->tm_mday,
       tf->tm_hour, tf->tm_min, tf->tm_sec);
   if (level == ERROR_LEVEL)//ERROR 
   {
       fprintf(stdout, "%s ERROR :[%s:%d]%s: ",szDate,file, line, func);       
   }
   else if (level == WARNING_LEVEL)
   {
       fprintf(stdout, "%s WARNING:[%s:%d]%s: ",szDate, file, line, func);
   }
   else if (level == INFO_LEVEL)
   {       
        fprintf(stdout, "%s INFO :[%s:%d]%s: ",szDate, file, line, func);    
   }
   else
   {
       fprintf(stdout, "%s DEBUG :[%s:%d]%s: ",szDate, file, line, func);       
   }
   
   va_list vaList;
   va_start(vaList, format);


   vfprintf(stdout, format, vaList);
   
   
   va_end(vaList);

   
   fprintf(stdout, "%c", '\n');
   
   return;
}

//SM3 哈希计算函数
static int mc_sm3(unsigned char *plain, int plain_len, unsigned char *hash, int *hash_len) {
    // 初始化 SM3 上下文
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Error creating SM3 context\n");
        return -1;
    }

    // 初始化 SM3 哈希计算
    if (EVP_DigestInit_ex(ctx, EVP_sm3(), NULL) != 1) {
        fprintf(stderr, "Error initializing SM3\n");
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    // 更新哈希计算数据
    if (EVP_DigestUpdate(ctx, plain, plain_len) != 1) {
        fprintf(stderr, "Error updating SM3\n");
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    // 完成哈希计算
    if (EVP_DigestFinal_ex(ctx, hash, (unsigned int *)hash_len) != 1) {
        fprintf(stderr, "Error finalizing SM3\n");
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    // 释放上下文
    EVP_MD_CTX_free(ctx);

    return 0; // 成功
}
static int HexStrToByteTrim(char* source, unsigned char* dest, int sourceLen)
{
    short i;
    int count = 0;
    int real_len = 0;
    unsigned char highByte, lowByte;
    unsigned char *data = (unsigned char*)calloc(sourceLen, 1);
    for(i=0; i < sourceLen; i++)
    {
        if ((source[i] == ' ') || (source[i] == '\r') || source[i] == '\n' || source[i] =='\t')
        {
            //memmove(source + i, source + i + 1, sourceLen -i -1);
           // count++;
        }
        else if(((source[i]>= '0')&&(source[i] <= '9'))||((source[i] >= 'a') &&(source[i] <= 'f')) || ((source[i] >= 'A')&&(source[i] <= 'F')))
        {
            data[count] = source[i];
            count++;
        }
    }
    MC_LOG_DEBUG("source Len is %d,data len is %d real data len is %d \n%s\n",sourceLen, count, count/2,data);
    for (i = 0; i < count; i += 2)
    {
        highByte = toupper(data[i]);
        lowByte  = toupper(data[i + 1]);
        if (highByte > 0x39)
            highByte -= 0x37;
        else
            highByte -= 0x30;			
        if (lowByte > 0x39)
            lowByte -= 0x37;
        else
            lowByte -= 0x30;

        dest[i / 2] = (highByte << 4) | lowByte;
    }
    //DebugOutPutHex_For_Test("hex is :", dest, count/2);
    real_len = count/2;
    MC_LOG_DEBUG("real ee len is %d\n",real_len);
    free(data);
    return real_len;
}

char *fix_random_bytes = "6BDD93B210F79415FE0F6388C1C932C208319FF7D7E99C972B3535C9F19A9FF9";
char *fix_dPrimeA_bytes = "04914C20251A59A2C311102944C600430A02285A0433144228142A1848004C00";
char *fix_w_bytes = "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F";
const char *sm2_param_a = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC";
const char *sm2_param_b = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";
const char *sm2_param_Gx = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
const char *sm2_param_Gy = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";
const char *sm2_param_n = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123";
// 错误处理函数
void handle_errors() {
    ERR_print_errors_fp(stderr);
}
int GenCLPKCMasterKey(
    unsigned char *MasterPrivateKey,
    int *MasterPrivateKeyLen,
    unsigned char *MasterPublicKey,
    int  *MasterPublicKeyLen)
{
   // 初始化 OpenSSL 库
   OpenSSL_add_all_algorithms();
   //ERR_load_crypto_strings();

   int ret = 0;
   unsigned char random_bytes[32] = {0};

   // if(RAND_bytes(random_bytes, sizeof(random_bytes)) != 1)
   // {
   //    MC_LOG_DEBUG("generate rand failed\n");
   //    return -1;
   // }
   BIGNUM *random_scalar = BN_new();

   if(random_scalar == NULL)
   {
       MC_LOG_ERR("new  random failed\n");
       return -1;
   }
   if(BN_rand(random_scalar, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) != 1)
   {
       MC_LOG_ERR("BN rand failed\n");
       return -1;
   }
   #if USE_FIX_DATA
   if(BN_hex2bn(&random_scalar, fix_random_bytes) == 0)
   {
       MC_LOG_ERR("BN HEX 2 BN failed\n");
       BN_free(random_scalar);
       return -1;        
   }
   #endif 
   EC_KEY *key = EC_KEY_new_by_curve_name(NID_sm2);
   if(key == NULL)
   {
       MC_LOG_ERR("new key failed\n");
       return -1;
   }
   
   const EC_GROUP *group = EC_KEY_get0_group(key);
   if(group == NULL)
   {
       MC_LOG_ERR("new group failed\n");
       return -1;
   }

   const EC_POINT *generator = EC_GROUP_get0_generator(group);
   if(generator == NULL)
   {
       MC_LOG_ERR("generator failed\n");
       return -1;
   }
     // 打印基点坐标
   char *generator_hex = EC_POINT_point2hex(group, generator, POINT_CONVERSION_UNCOMPRESSED, NULL);
   MC_LOG_DEBUG("SM2 Base Point (Generator): %s\n", generator_hex);

   char *random_scalar_hex = BN_bn2hex(random_scalar);
   MC_LOG_DEBUG("Random Scalar: %s\n", random_scalar_hex);
   OPENSSL_free(random_scalar_hex);
   // 创建一个新的点，用于存储点乘结果
   EC_POINT *result_point = EC_POINT_new(group);
   if (result_point == NULL) {
       handle_errors();
   }
   // 进行点乘运算：result_point = random_scalar * generator
   if (EC_POINT_mul(group, result_point, NULL, generator, random_scalar, NULL) != 1)
   {
       handle_errors();
   }
   // 打印点乘结果
   char *result_point_hex = EC_POINT_point2hex(group, result_point, POINT_CONVERSION_UNCOMPRESSED, NULL);

   MC_LOG_DEBUG("Point Multiplication Result: %s\n", result_point_hex);
   OPENSSL_free(result_point_hex);

   BN_bn2bin(random_scalar, MasterPrivateKey);

   *MasterPrivateKeyLen = 32;
   BIGNUM *x = BN_new();
   BIGNUM *y = BN_new();
   if ((x == NULL) || (y == NULL))
   {
       MC_LOG_ERR("new x y failed\n");
       goto end;
   }
   if(EC_POINT_get_affine_coordinates(group, result_point,x,y, NULL) != 1)
   {
       MC_LOG_ERR("get x y failed\n");
       goto end;
   }
   BN_bn2bin(x, MasterPublicKey);
   BN_bn2bin(y, MasterPublicKey + 32);

   *MasterPublicKeyLen = 64;
end:
   // 清理资源
   EC_POINT_free(result_point);
   BN_free(random_scalar);
   EC_KEY_free(key);
   BN_free(x);
   BN_free(y);
   EVP_cleanup();
   //ERR_free_strings();
   return ret;
}

int GenUAINFO(unsigned char *dPreA, int *dPreALen, unsigned char *UA, int *UALen)
{
    int ret = 0;
    OpenSSL_add_all_algorithms();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
    if(group == NULL)
    {
        MC_LOG_ERR("group err\n");
        return -1;
    }
    const BIGNUM *order = EC_GROUP_get0_order(group);
    if(order == NULL)
    {
        MC_LOG_ERR("order err\n");
        return -1;
    }

    // 打印阶数 n
    char *order_hex = BN_bn2hex(order);
    MC_LOG_DEBUG("SM2 Curve Order (n): %s\n", order_hex);
    OPENSSL_free(order_hex);

    BIGNUM *range = BN_new();
    if(range == NULL)
    {
        MC_LOG_ERR("new range failed\n");
        return -1;
    }
    BN_copy(range, order);
    BIGNUM *dPrimeA = BN_new();
    if(dPrimeA == NULL)
    {
        MC_LOG_ERR("new dPrimeA failed\n");
    }
    BN_sub_word(range, 1);
    do {
        BN_rand_range(dPrimeA, range);
    } while(BN_cmp(dPrimeA, BN_value_one()) < 0 || BN_cmp(dPrimeA, range) > 0);// 0 false exit 
    
    #if USE_FIX_DATA
    if(BN_hex2bn(&dPrimeA, fix_dPrimeA_bytes) == 0)
    {
        MC_LOG_ERR("BN HEX 2 BN failed\n");
        BN_free(dPrimeA);
        return -1;        
    }
    #endif 

    char *primeA_hex = BN_bn2hex(dPrimeA);
    MC_LOG_DEBUG("Random primeA: %s\n", primeA_hex);
    OPENSSL_free(primeA_hex);
    *dPreALen = BN_bn2bin(dPrimeA, dPreA);
    const EC_POINT *generator = EC_GROUP_get0_generator(group);
    if(generator == NULL)
    {
        MC_LOG_ERR("generator failed\n");
        return -1;
    }

    // 创建一个新的点，用于存储点乘结果
    EC_POINT *result_point = EC_POINT_new(group);
    if (result_point == NULL) {
        handle_errors();
    }
    // 进行点乘运算：result_point = random_scalar * generator
    if (EC_POINT_mul(group, result_point, NULL, generator, dPrimeA, NULL) != 1)
    {
        handle_errors();
    }
    // 打印点乘结果
    char *result_point_hex = EC_POINT_point2hex(group, result_point, POINT_CONVERSION_UNCOMPRESSED, NULL);

    MC_LOG_DEBUG("Point Multiplication Result: %s\n", result_point_hex);
    OPENSSL_free(result_point_hex);
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    if(EC_POINT_get_affine_coordinates(group, result_point,x,y, NULL) != 1)
    {
        MC_LOG_ERR("get x y failed\n");
        goto end;
    }

    BN_bn2bin(x, UA);
    BN_bn2bin(y, UA + 32);
    *UALen = 64;
    ret = 0;
end:
 
    EC_POINT_free(result_point);

    BN_free(range);

    EC_GROUP_free(group); 

    BN_free(dPrimeA);


    BN_free(x);

    BN_free(y);

    EVP_cleanup();
    return ret;
}

int CalHAINFO(unsigned char *UserId, int UserIdLen, unsigned char *pubKey, int pubKeyLen, unsigned char *HA, int *HALen)
{
    int ret = 0;
    unsigned char plain[256] = {0};
    unsigned char hash[32] = {0};
    int hash_len = 32;
    int plain_len = sizeof(plain);
    int len = UserIdLen*8;
    unsigned char a[32] = {0};
    unsigned char b[32] = {0};
    unsigned char xG[64] = {0};
    unsigned char yG[64] = {0};
    plain[0] = (unsigned char)(len >> 8)&(0xFF);
    plain[1] = (unsigned char)(len & 0xFF);
    memcpy(plain + 2, UserId, UserIdLen);
    HexStrToByteTrim(sm2_param_a, a, strlen(sm2_param_a));
    memcpy(plain + 2 + UserIdLen, a, 32);
    HexStrToByteTrim(sm2_param_b, b, strlen(sm2_param_b));
    memcpy(plain + 2 + UserIdLen + 32, b, 32);
    HexStrToByteTrim(sm2_param_Gx, xG, strlen(sm2_param_Gx));
    memcpy(plain + 2 + UserIdLen + 32 + 32, xG, 32);
    HexStrToByteTrim(sm2_param_Gy, yG, strlen(sm2_param_Gy));
    memcpy(plain + 2 +UserIdLen + 32 + 32 + 32, yG, 32);
    memcpy(plain + 2 + UserIdLen + 32 + 32 + 32 + 32, pubKey, pubKeyLen);
    plain_len = 2 + UserIdLen + 32 + 32 + 32+32 + pubKeyLen;
    MC_LOG_DEBUG("plain len is %d\n", plain_len);
//    cy_hex_dump("plain :", plain, plain_len);

    mc_sm3(plain, plain_len, hash,  &hash_len);
//    cy_hex_dump("hashA", hash, hash_len);
    memcpy(HA, hash,32);
    *HALen = hash_len;
    return ret;
}

//KGC 
//K2：KGC产生随机数w[1,n−1]；
//K3：KGC计算WA=[w]G+UA；
int CalWAInfo(unsigned char *UA, int UA_len, unsigned char *WA, int *WA_len, unsigned char *wb, int *wLen)
{
    int ret = 0;
    OpenSSL_add_all_algorithms();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
    if(group == NULL)
    {
        MC_LOG_ERR("group err\n");
        return -1;
    }
    const BIGNUM *order = EC_GROUP_get0_order(group);
    if(order == NULL)
    {
        MC_LOG_ERR("order err\n");
        return -1;
    }
    // 打印阶数 n
    char *order_hex = BN_bn2hex(order);
    MC_LOG_DEBUG("SM2 Curve Order (n): %s\n", order_hex);
    OPENSSL_free(order_hex);

    BIGNUM *range = BN_new();
    if(range == NULL)
    {
        MC_LOG_ERR("new range failed\n");
        return -1;
    }
    BN_copy(range, order);

    BIGNUM *b_w = BN_new();
    if(b_w == NULL)
    {
        MC_LOG_ERR("new w failed\n");
    }
    BN_sub_word(range, 1);
    do {
        BN_rand_range(b_w, range);
    } while (BN_cmp(b_w, BN_value_one()) < 0 || BN_cmp(b_w, range) > 0);// 0 false exit 
    
    #if USE_FIX_DATA
    if(BN_hex2bn(&b_w, fix_w_bytes) == 0)
    {
        MC_LOG_ERR("BN HEX 2 BN failed\n");
        BN_free(b_w);
        return -1;        
    }
    #endif 

    char *w_hex = BN_bn2hex(b_w);
    MC_LOG_DEBUG("Random w: %s\n", w_hex);
    OPENSSL_free(w_hex);

    *wLen = BN_bn2bin(b_w, wb);
    
    const EC_POINT *generator = EC_GROUP_get0_generator(group);
    if(generator == NULL)
    {
        MC_LOG_ERR("generator failed\n");
        return -1;
    }

    // 创建一个新的点，用于存储点乘结果
    EC_POINT *result_point = EC_POINT_new(group);
    if (result_point == NULL) {
        handle_errors();
    }
    // 进行点乘运算：result_point = random_scalar * generator
    if (EC_POINT_mul(group, result_point, NULL, generator, b_w, NULL) != 1)
    {
        handle_errors();
    }
    // 打印点乘结果
    char *result_point_hex = EC_POINT_point2hex(group, result_point, POINT_CONVERSION_UNCOMPRESSED, NULL);

    MC_LOG_DEBUG("Point Multiplication Result: %s\n", result_point_hex);
    //OPENSSL_free(result_point_hex);
    BIGNUM *xUA = BN_new();
    BIGNUM *yUA = BN_new();
    
    EC_POINT *UA_point = EC_POINT_new(group);    
    xUA = BN_bin2bn(UA, 32, NULL);
    yUA = BN_bin2bn(UA + 32, 32,NULL);

    ret = EC_POINT_set_affine_coordinates(group, UA_point, xUA, yUA, NULL);
    if(ret != 1)
    {
        MC_LOG_ERR("set coordinates UA point failed\n");
        goto end;
    }
    EC_POINT *WA_point = EC_POINT_new(group);
    if(WA_point == NULL)
    {
        MC_LOG_ERR("new wa point failed\n");
        goto end;
    }
    //WA=[w]G+UA=(xWA,yWA):
    ret = EC_POINT_add(group, WA_point, result_point, UA_point, NULL);
    if(ret != 1)
    {
        MC_LOG_ERR("point add failed\n");
        goto end;
    }
    ret = 0;
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    if(EC_POINT_get_affine_coordinates(group, WA_point,x,y, NULL) != 1)
    {
        MC_LOG_ERR("get x y failed\n");
        goto end;
    }
 
    result_point_hex = EC_POINT_point2hex(group, WA_point, POINT_CONVERSION_UNCOMPRESSED, NULL);

    MC_LOG_DEBUG("WA Point ADD Result: %s\n", result_point_hex);
    OPENSSL_free(result_point_hex);
    BN_bn2bin(x, WA);
    BN_bn2bin(y, WA + 32);
    *WA_len = 64;

end:
    
    EC_POINT_free(result_point);
    EC_POINT_free(WA_point);
    BN_free(range);
    EC_GROUP_free(group); 
    BN_free(b_w);
    BN_free(xUA);
    BN_free(yUA);
    BN_free(x);
    BN_free(y);
    EVP_cleanup();
    return ret;
}

//K4:lamda=H256(xWA‖yWA‖HA) mod n 
int CalLamdaInfo(unsigned char *WA, int WA_len, unsigned char *HA, int HALen, unsigned char *lamada, int *lamda_len)
{
    int ret = 0;
    unsigned char lamda_plain[96] = {0};
    unsigned char lamda_hash[32] = {0};
    int lamda_hash_len = 32;
    OpenSSL_add_all_algorithms();
    int lamda_plain_len = WA_len + HALen;
    MC_LOG_DEBUG("lamda plain len is %d\n", lamda_plain_len);

    memcpy(lamda_plain, WA, WA_len);
    memcpy(lamda_plain + WA_len, HA, HALen);
//    cy_hex_dump("plain is ", lamda_plain, lamda_plain_len);
    mc_sm3(lamda_plain, lamda_plain_len, lamda_hash, &lamda_hash_len);
//    cy_hex_dump("hash", lamda_hash, lamda_hash_len);
    BIGNUM *b_lamada = BN_new();
    BIGNUM *b_hash = BN_new();
    BIGNUM *n = BN_new();
    BN_CTX *ctx = BN_CTX_new(); // 创建上下文
    b_hash = BN_bin2bn(lamda_hash, lamda_hash_len,NULL);
    BN_hex2bn(&n, sm2_param_n);
    ret = BN_mod(b_lamada, b_hash, n, ctx);
    if(ret != 1)
    {
        MC_LOG_ERR("mod failed\n");
        goto end;
    }
    char *hex_str = BN_bn2hex(b_lamada);
    MC_LOG_INFO("lamada : %s\n", hex_str);
    OPENSSL_free(hex_str);

    ret = BN_bn2bin(b_lamada, lamada);
    if(ret == 0)
    {
        MC_LOG_ERR("bn 2 bin failed\n");
        goto end;
    }
    ret = 0;
    *lamda_len = 32;

end:
    BN_CTX_free(ctx);
    BN_free(b_lamada);
    BN_free(b_hash);
    BN_free(n);
    EVP_cleanup();
    return ret;
}

//K5：KGC计算tA=(w + λ*ms) mod n，并KGC向用户A返回tA和WA；
int CaltAInfo(unsigned char *w, int wLen, unsigned char *lamada, int lamadaLen, unsigned char *ms, int msLen, unsigned char *tA, int *tALen)
{
     int ret = 0;
     OpenSSL_add_all_algorithms();
     BIGNUM *b_w = BN_new();
     BIGNUM *b_lamada = BN_new();
     BIGNUM *b_ms = BN_new();
     BIGNUM *b_n = BN_new();
     BIGNUM *b_tA = BN_new();
     BIGNUM *result = BN_new();
     BIGNUM *add_result = BN_new();
     BN_CTX *ctx = BN_CTX_new();
     char *result_str = NULL;
     b_w = BN_bin2bn(w, wLen, NULL);
     b_ms = BN_bin2bn(ms, msLen, NULL);
     b_lamada = BN_bin2bn(lamada, lamadaLen,NULL);

    if(1 != BN_mul(result, b_lamada, b_ms, ctx))
    {
        MC_LOG_ERR("BN mul failed\n");
        goto end;
    }
    result_str = BN_bn2hex(result);
    MC_LOG_DEBUG("Result of  lamada* ms: %s\n", result_str);
    
    ret = BN_add(add_result, b_w, result);
    if(ret != 1)
    {
        MC_LOG_ERR("BN ADD failed\n");
        goto end;
    }
    BN_hex2bn(&b_n, sm2_param_n);
    ret = BN_mod(b_tA, add_result, b_n, ctx);
    if(ret != 1)
    {
        MC_LOG_ERR("mod failed\n");
        goto end;
    }
    char *hex_str = BN_bn2hex(b_tA);
    MC_LOG_INFO("tA : %s\n", hex_str);
    OPENSSL_free(hex_str);

    *tALen = BN_bn2bin(b_tA, tA);
    ret = 0;
end:
    BN_free(b_w);
    BN_free(b_lamada);
    BN_free(b_ms);
    BN_free(result);
    BN_free(add_result);
    BN_free(b_n);
    BN_free(b_tA);
    OPENSSL_free(result_str);
    EVP_cleanup();
    return ret;
}


//用户A计算dA=(tA+d'A) mod n；
int CaldAValue(unsigned char *tA, int tALen, unsigned char *dPreA, int dPreALen, unsigned char *dA, int *dALen)
{
    int ret = 0;
    OpenSSL_add_all_algorithms();
    BIGNUM *b_tA = BN_new();

    BIGNUM *b_dPreA = BN_new();
    BIGNUM *b_dA = BN_new();
    BIGNUM *b_n = BN_new();
    BIGNUM *result = BN_new();

    BN_CTX *ctx = BN_CTX_new();
    b_tA = BN_bin2bn(tA, tALen, NULL);
    b_dPreA = BN_bin2bn(dPreA, dPreALen, NULL);
    BN_hex2bn(&b_n, sm2_param_n);
    ret = BN_add(result, b_dPreA, b_tA);
    if(ret != 1)
    {
        MC_LOG_ERR("BN ADD failed\n");
        goto end;
    }
    ret = BN_mod(b_dA, result, b_n, ctx);
    if(ret != 1)
    {
        MC_LOG_ERR("mod failed\n");
        goto end;
    }
    *dALen = BN_bn2bin(b_dA, dA);
    ret = 0;
 end:
    if(ctx)
        BN_CTX_free(ctx);
    if(b_dA)
        BN_free(b_dA);
    if(b_dPreA)
        BN_free(b_dPreA);
    if(b_n)
        BN_free(b_n);
    if(b_tA)
        BN_free(b_tA);
    if(result) 
        BN_free(result);
    
    return ret;
}

//A3: 计算PA=WA+[lmada]Ppub；//点乘 点加
int CalPAInfo(unsigned char *WA, int WA_len, unsigned char *lamda, int lamda_len, unsigned char *MasterPublicKey, int MasterPublicKeyLen, unsigned char *PA, int *PALen)
{
    int ret = 0;
    OpenSSL_add_all_algorithms();

    BIGNUM *b_lamada = BN_new();
    BIGNUM *b_xWA = BN_new();
    BIGNUM *b_yWA = BN_new();
    BIGNUM *result = BN_new();
    BIGNUM *add_result = BN_new();
    BIGNUM *b_xPpub = BN_new();
    BIGNUM *b_yPpub = BN_new();
    BIGNUM *b_xPA = BN_new();
    BIGNUM *b_yPA = BN_new();
    char *result_str = NULL;
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
    if(group == NULL)
    {
        MC_LOG_ERR("EC_GROUP_new_by_curve_name failed\n");
        goto end;
    }
    EC_POINT *WA_point = EC_POINT_new(group);
    EC_POINT *result_point = EC_POINT_new(group);
    EC_POINT *PA_point = EC_POINT_new(group);
    EC_POINT *Ppub_point = EC_POINT_new(group);
    BN_CTX *ctx = BN_CTX_new();
    b_lamada = BN_bin2bn(lamda, lamda_len, NULL);
    b_xWA = BN_bin2bn(WA, 32, NULL);
    b_yWA = BN_bin2bn(WA+32, 32, NULL);
    ret = EC_POINT_set_affine_coordinates(group, WA_point, b_xWA, b_yWA, ctx);
    if( ret != 1)
    {
        MC_LOG_ERR("WA point EC_POINT_set_affine_coordinates failed\n");
        goto end;
    }
    b_xPpub = BN_bin2bn(MasterPublicKey, 32, NULL);
    b_yPpub = BN_bin2bn(MasterPublicKey+32, 32, NULL);
    ret = EC_POINT_set_affine_coordinates(group, Ppub_point, b_xPpub, b_yPpub, ctx);
    if( ret != 1)
    {
        MC_LOG_ERR("Ppub point EC_POINT_set_affine_coordinates failed\n");
        goto end;
    }
    ret = EC_POINT_mul(group, result_point, NULL, Ppub_point, b_lamada, ctx);
    if(ret != 1)
    {
        MC_LOG_ERR("EC_POINT_mul failed\n");
        goto end;
    }
    
    ret = EC_POINT_add(group,PA_point,WA_point, result_point,NULL);
    if(ret != 1)
    {
        MC_LOG_ERR("EC_POINT_add failed\n");
        goto end;
    }

    ret = EC_POINT_get_affine_coordinates(group, PA_point, b_xPA, b_yPA, ctx);
    if(ret != 1)
    {
        MC_LOG_ERR("PA point EC_POINT_get_affine_coordinates failed\n");
        goto end;
    }
    BN_bn2bin(b_xPA, PA);
    BN_bn2bin(b_yPA, PA+32);
    *PALen = 64;
    ret = 0;
end:
    if(group)
        EC_GROUP_free(group);
    if(WA_point)
        EC_POINT_free(WA_point);
    if(result_point)
        EC_POINT_free(result_point);
    if(PA_point)
        EC_POINT_free(PA_point);
    if(ctx)
        BN_CTX_free(ctx);
    if(b_lamada)
        BN_free(b_lamada);
    if(b_xWA)
        BN_free(b_xWA);
    if(b_yWA)
        BN_free(b_yWA);
    if(result)
        BN_free(result);
    if(add_result)
        BN_free(add_result);
    if(b_xPpub)
        BN_free(b_xPpub);
    if(b_yPpub)
        BN_free(b_yPpub);
    if(b_xPA)
        BN_free(b_xPA);
    if(b_yPA)
        BN_free(b_yPA);
    if(result_str)
        OPENSSL_free(result_str);
    return ret;
}

//A4.计算P'A=[dA]G
int CalprePAInfo(unsigned char *dA, int dALen, unsigned char *PA, int *PALen)
{
    int ret = 0;
    OpenSSL_add_all_algorithms();

    //A4.计算P'A=[dA]G
    BIGNUM *b_dA = BN_new();
    b_dA = BN_bin2bn(dA, dALen, NULL);
    if(b_dA == NULL)
    {
        MC_LOG_ERR("bn 2 bin failed\n");
        goto end;
    }
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
    if(group == NULL)
    {
        MC_LOG_ERR("EC_GROUP_new_by_curve_name failed\n");
        goto end;
    }
    EC_POINT *result_A = EC_POINT_new(group);
    if(result_A == NULL)
    {
        MC_LOG_ERR("EC_POINT_new failed\n");
        goto end;
    }
    EC_POINT *G = EC_GROUP_get0_generator(group);
    if(G == NULL)
    {
        MC_LOG_ERR("EC_GROUP_get0_generator failed\n");
        goto end;
    }
    ret = EC_POINT_mul(group, result_A, NULL, G, b_dA, NULL);
    if(ret != 1)
    {
        MC_LOG_ERR("EC_POINT_mul failed\n");
        goto end;
    }
    char *result_point_hex = EC_POINT_point2hex(group, result_A, POINT_CONVERSION_UNCOMPRESSED, NULL);
    if(result_point_hex == NULL)
    {
        MC_LOG_ERR("EC_POINT_point2hex failed\n");
        goto end;
    }
    OPENSSL_free(result_point_hex);
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    ret = EC_POINT_get_affine_coordinates_GFp(group, result_A, x, y, NULL);
    if(ret != 1)
    {
        MC_LOG_ERR("EC_POINT_get_affine_coordinates_GFp failed\n");
        goto end;
    }
    BN_bn2bin(x, PA);
    BN_bn2bin(y, PA+32);
    *PALen = 64;
    ret = 0;
end:
    if(group)
        EC_GROUP_free(group);
    if(result_A)
        EC_POINT_free(result_A);
   // if(G)
    //    EC_POINT_free(G);
    if(b_dA)
        BN_free(b_dA);
    
    return ret;
}



//SIGN(param,HA,xWA‖yWA‖M,O,dA)
int CLPKC_Sign(unsigned char *message, int messageLen, unsigned char *HA, int HALen, unsigned char *WA, int WA_len, unsigned char *dA, int dALen, unsigned char *Signature, int *SignatureLen)
{
    int ret = 0;
    OpenSSL_add_all_algorithms();
    int msg_len = 0;
    unsigned char *msg = (unsigned char *)malloc(messageLen + HALen + WA_len + 1);
    if(msg == NULL)
    {
        MC_LOG_ERR("malloc failed\n");
        goto end;
    }
//    cy_hex_dump("HA", HA, HALen);
//    cy_hex_dump("WA", WA, WA_len);
//    cy_hex_dump("message", message, messageLen);
    memcpy(msg,HA, HALen);
    memcpy(msg + HALen, WA, WA_len);
    memcpy(msg + HALen + WA_len, message, messageLen);
    msg_len = messageLen + WA_len + HALen;
    //计算e
    unsigned char e[32] = {0};
    int eLen = 32;
    ret = mc_sm3(msg, msg_len, e, &eLen);
    if(ret != 0)
    {
        MC_LOG_ERR("sm3 failed\n");
        goto end;
    }
//    cy_hex_dump("e", e, eLen);
    BIGNUM *b_private_key = BN_bin2bn(dA, dALen, NULL);
    if(b_private_key == NULL)
    {
        MC_LOG_ERR("BN_bin2bn failed\n");
        goto end;
    }
    #if 1
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if(ec_key == NULL)
    {
        MC_LOG_ERR("EC_KEY_new_by_curve_name failed\n");
        goto end;
    }
    ret = EC_KEY_set_private_key(ec_key, b_private_key);
    if(ret != 1)
    {
        MC_LOG_ERR("EC_KEY_set_private_key failed\n");
        goto end;
    }
    #endif

    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
    if(group == NULL)
    {
        MC_LOG_ERR("EC_GROUP_new_by_curve_name failed\n");
        goto end;
    }
    const EC_POINT *generator = EC_GROUP_get0_generator(group);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    if(order == NULL)
    {
        MC_LOG_ERR("EC_GROUP_get0_order failed\n");
        goto end;
    }
    unsigned char *fixed_k = "34914C20251A59A2C311102944C600430A02285A0433144228142A1848004C14";
    BIGNUM *b_k = BN_new();
    #if USE_FIX_DATA
    BN_hex2bn(&b_k, fixed_k);
    #else
    BIGNUM *range = BN_new();
    BN_copy(range, order);
    BN_sub_word(range, 1);
    do{
        BN_rand_range(b_k, range);  
    }while(BN_cmp(b_k, BN_value_one()) < 0 || BN_cmp(b_k, range)> 0);

    #endif

    EC_POINT *kG_point  = EC_POINT_new(group);
    if(kG_point == NULL)
    {
        MC_LOG_ERR("EC_POINT_new failed\n");
        goto end;
    }
    //A4. Calculate kG
    ret = EC_POINT_mul(group, kG_point, b_k, generator, NULL, NULL);
    if(ret != 1)
    {
        MC_LOG_ERR("EC_POINT_mul failed\n");
        goto end;
    }
    char *result_point_hex = EC_POINT_point2hex(group, kG_point,POINT_CONVERSION_UNCOMPRESSED, NULL);
    MC_LOG_DEBUG("kG: %s\n", result_point_hex);
    BIGNUM *xkG = BN_new();
    BIGNUM *ykG = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, kG_point, xkG, ykG, NULL);
    MC_LOG_DEBUG("xkG: %s\n", BN_bn2hex(xkG));
    MC_LOG_DEBUG("ykG: %s\n", BN_bn2hex(ykG));

    //A5 r= （e + x1)mod n


    BIGNUM *r =BN_new();
    BIGNUM *s =BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *result_add = BN_new();
    if(result_add == NULL)
    {
        MC_LOG_ERR("BN_new failed\n");
        goto end;
    }
    BIGNUM *b_n = BN_new();
    if(b_n == NULL)
    {
        MC_LOG_ERR("BN_new failed\n");
        goto end;
    }
    BIGNUM *b_e = BN_bin2bn(e, eLen, NULL);
    if(b_e == NULL)
    {
        MC_LOG_ERR("BN_bin2bn failed\n");
        goto end;
    }

    BN_add(result_add, b_e, xkG);
    BN_hex2bn(&b_n, sm2_param_n);
    //BN_mod(r, result_add, order, ctx);
    BN_mod(r, result_add, b_n, ctx);
    if(1 == BN_is_zero(r))
    {
        MC_LOG_ERR("r is zero\n");
        goto end;
    }
    BIGNUM *rksum  = BN_new();
    if(rksum == NULL)
    {
        MC_LOG_ERR("BN_new failed\n");
        goto end;
    }
    ret = BN_add(rksum, r, b_k);
    if(ret != 1)
    {
        MC_LOG_ERR("rk sum BN_add failed\n");
        goto end;
    }
    if(0 == BN_cmp(rksum, b_n))
    {
        MC_LOG_ERR("rk sum is n\n");
        goto end;
    }
    BIGNUM *dPlus1ModN = BN_new();
    if(dPlus1ModN == NULL)
    {
        MC_LOG_ERR("BN_new failed\n");
        goto end;
    }
    if (NULL == BN_copy(dPlus1ModN, b_private_key))
    {
        MC_LOG_ERR("BN_copy failed is NULL\n");
        goto end;
    }
    BN_add_word(dPlus1ModN, 1);

    BN_mod_inverse(dPlus1ModN, dPlus1ModN, b_n, ctx);
    BIGNUM *b_rdA = BN_new();
    if(b_rdA == NULL)
    {
        MC_LOG_ERR("b rdA BN_new failed\n");
        goto end;
    }
    ret = BN_mul(b_rdA, r, b_private_key, ctx);
    if(ret != 1)
    {
        MC_LOG_ERR("b rdA BN_mul failed\n");
        goto end;
    }
    ret = BN_mod_sub(s, b_k, b_rdA, b_n, ctx);
    if(ret != 1)
    {
        MC_LOG_ERR("s BN_mod_sub failed\n");
        goto end;
    }
    ret = BN_mod_mul(s, dPlus1ModN, s, b_n, ctx);
    if(ret != 1)
    {
        MC_LOG_ERR("s BN_mod_mul failed\n");
        goto end;
    }
    //ECDSA_SIG_get0(sig, &r, &s);

    MC_LOG_DEBUG("r: %s\n", BN_bn2hex(r));
    MC_LOG_DEBUG("s: %s\n", BN_bn2hex(s));
    *SignatureLen = BN_num_bytes(r) + BN_num_bytes(s);
    MC_LOG_DEBUG("SignatureLen: %d\n", *SignatureLen);
    ECDSA_SIG *sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(sig, r, s);
    *SignatureLen = i2d_ECDSA_SIG(sig, &Signature);
    MC_LOG_DEBUG("i2d SignatureLen: %d\n", *SignatureLen);

    ret = 0;
end:

    if(msg)
        free(msg);
    // if(ec_key)
    //     EC_KEY_free(ec_key);
    if(sig) 
        ECDSA_SIG_free(sig);
    if(rksum)
        BN_free(rksum);
    if(dPlus1ModN)
        BN_free(dPlus1ModN);
    if(kG_point)
        EC_POINT_free(kG_point);
    if(group)
        EC_GROUP_free(group);
    if(b_k)
        BN_free(b_k);
    if(b_private_key)
        BN_free(b_private_key);
    if(ctx)
        BN_CTX_free(ctx);
    if(result_add)
        BN_free(result_add);
    if(b_e)
        BN_free(b_e);
    return ret;
}

int CLPKC_Verify(unsigned char *PA, int PALen, unsigned char *message, int messageLen, unsigned char *HA, int HALen, unsigned char *WA, int WA_len, unsigned char *Signature, int SignatureLen)
{
    int ret = 0;
    OpenSSL_add_all_algorithms();
    int msg_len = 0;
    unsigned char *msg = (unsigned char *)malloc(messageLen + HALen + WA_len + 1);
    if(msg == NULL)
    {
        MC_LOG_ERR("malloc failed\n");
        goto end;
    }
//    cy_hex_dump("HA", HA, HALen);
//    cy_hex_dump("WA", WA, WA_len);
//    cy_hex_dump("message", message, messageLen);
    memcpy(msg,HA, HALen);
    memcpy(msg + HALen, WA, WA_len);
    memcpy(msg + HALen + WA_len, message, messageLen);
    msg_len = messageLen + WA_len + HALen;
    //计算e
    unsigned char e[32] = {0};
    int eLen = 32;
    ret = mc_sm3(msg, msg_len, e, &eLen);
    if(ret != 0)
    {
        MC_LOG_ERR("sm3 failed\n");
        goto end;
    }
//    cy_hex_dump("e", e, eLen);
    BIGNUM *b_e = BN_new();
    b_e = BN_bin2bn(e, eLen, NULL);
    if(b_e == NULL)
    {
        MC_LOG_ERR("BN_bin2bn failed\n");
        ret = -1;
        goto end;
    }

    ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &Signature, SignatureLen);
    if(sig == NULL)
    {
        MC_LOG_ERR("d2i_ECDSA_SIG failed\n");
        goto end;
    }

    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;
    BIGNUM *one = BN_new();
    BIGNUM *b_n = BN_new();
    BIGNUM *b_result = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    ECDSA_SIG_get0(sig, &r, &s);
    MC_LOG_DEBUG("r: %s\n", BN_bn2hex(r));
    MC_LOG_DEBUG("s: %s\n", BN_bn2hex(s));
    BN_hex2bn(&b_n, sm2_param_n);
    BN_hex2bn(&one, "1");
    BN_sub(b_result, b_n, one);
    if(BN_cmp(r, one) < 0 || BN_cmp(r, b_result) > 0)
    {
        MC_LOG_ERR("r is not in [1, n-1]\n");
        ret = -1;
        goto end;
    }
    if(BN_cmp(s, one) < 0 || BN_cmp(s, b_result) > 0)
    {
        MC_LOG_ERR("s is not in [1, n-1]\n");
        ret = -1;
        goto end;
    }
    BIGNUM *t = BN_new();
    if(t == NULL)
    {
        MC_LOG_ERR("t BN_new failed\n");
        goto end;
    }
    ret = BN_mod_add(t, r, s, b_n, ctx);
    if(ret != 1)
    {
        MC_LOG_ERR("BN_mod_add failed\n");
        ret = -1;
        goto end;
    }

    if(1 == BN_is_zero(t))
    {
        MC_LOG_ERR("t is zero\n");
        ret = -1;
        goto end;
    }
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
    if(group == NULL)
    {
        MC_LOG_ERR("EC_GROUP_new_by_curve_name failed\n");
        goto end;
    }
    EC_POINT *generator = EC_GROUP_get0_generator(group);
    if(generator == NULL)
    {
        MC_LOG_ERR("EC_GROUP_get0_generator failed\n");
        ret = -1;
        goto end;
    }
    EC_POINT *sG = EC_POINT_new(group);
    if(sG == NULL)
    {
        MC_LOG_ERR("EC_POINT_new failed\n");
        ret = -1;
        goto end;
    }
    ret = EC_POINT_mul(group,sG,NULL,generator, s, NULL);
    if(ret != 1)
    {
        MC_LOG_ERR("EC_POINT_mul failed\n");
        ret = -1;
        goto end;
    }
    EC_POINT *PA_point = EC_POINT_new(group);
    if(PA_point == NULL)
    {
        MC_LOG_ERR("EC_POINT_new failed\n");
        ret = -1;
        goto end;
    }

    BIGNUM *PA_x = BN_new();
    BIGNUM *PA_y = BN_new();
    PA_x = BN_bin2bn(PA, 32, NULL);
    PA_y = BN_bin2bn(PA +32, 32, NULL);
    ret = EC_POINT_set_affine_coordinates(group, PA_point, PA_x, PA_y, NULL);
    if(ret != 1)
    {
        MC_LOG_ERR("EC_POINT_set_affine_coordinates failed\n");
        ret = -1;
        goto end;
    }
    EC_POINT *tPA = EC_POINT_new(group);
    if(tPA == NULL)
    {
        MC_LOG_ERR("EC_POINT_new failed\n");
        ret = -1;
        goto end;
    }
    ret = EC_POINT_mul(group, tPA, NULL, PA_point, t, NULL);
    if(ret != 1)
    {
        MC_LOG_ERR("EC_POINT_mul failed\n");
        ret = -1;
        goto end;
    }
    EC_POINT *point = EC_POINT_new(group);
    if(point == NULL)
    {
        MC_LOG_ERR("EC_POINT_new failed\n");
        ret = -1;
        goto end;
    }
    ret = EC_POINT_add(group, point, sG, tPA, NULL);
    if(ret != 1)
    {
        MC_LOG_ERR("EC_POINT_add failed\n");
        ret = -1;
        goto end;
    }

    char *result_point_hex = EC_POINT_point2hex(group,point,POINT_CONVERSION_UNCOMPRESSED,NULL);
    if(result_point_hex == NULL)
    {
        MC_LOG_ERR("EC_POINT_point2hex failed\n");
        ret = -1;
        goto end;
    }
    MC_LOG_DEBUG("result point hex is %s\n", result_point_hex);
    OPENSSL_free(result_point_hex);
    BIGNUM *b_x1 = BN_new();
    BIGNUM *b_y1 = BN_new();
    ret = EC_POINT_get_affine_coordinates_GFp(group, point, b_x1, b_y1, NULL);
    if(ret != 1)
    {
        MC_LOG_ERR("EC_POINT_get_affine_coordinates_GFp failed\n");
        ret = -1;
        goto end;
    }
    BIGNUM *b_R = BN_new();
    if(b_R == NULL)
    {
        MC_LOG_ERR("b_R BN_new failed\n");
        ret = -1;
        goto end;
    }
    BN_mod_add(b_R, b_e, b_x1, b_n, ctx);
    if(!b_R)
    {
        MC_LOG_ERR("BN_mod_add failed\n");
        ret = -1;
        goto end;
    }
    if(0 != BN_cmp(b_R, r))
    {
        MC_LOG_ERR("b_R != r\n");
        ret = -1;
    }
    ret = 0;
    end:

    if(ctx)
        BN_CTX_free(ctx);

    if(b_result)
        BN_free(b_result);

    if(t)
        BN_free(t);

    if(b_n)
        BN_free(b_n);

    if(one)
        BN_free(one);

    // if(s)
    //     BN_free(s);
    //     printf("%d\n", __LINE__);

    // if(r)
    //     BN_free(r);
    //     printf("%d\n", __LINE__);
    if(sig)
        ECDSA_SIG_free(sig);
    if(msg)
        free(msg);
    if(group)
        EC_GROUP_free(group);
    if(point)
        EC_POINT_free(point);
    if(tPA)
        EC_POINT_free(tPA);
    if(PA_point)
        EC_POINT_free(PA_point);
    if(sG)
        EC_POINT_free(sG);
    if(b_x1)
        BN_free(b_x1);
    if(b_y1)
        BN_free(b_y1);
    if(b_R)
        BN_free(b_R);
    return 0;
}

int CLPKC_Encrypt(unsigned char *PA, int PALen, unsigned char *message, int messageLen, unsigned char *Ciphertext,  int *CiphertextLen)
{
    int ret = 0;
    cy_openssl_version();

    #if 1
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if (ec_key == NULL)
    {
        MC_LOG_ERR("EC_KEY_new_by_curve_name failed\n");
        ret = -1;
        goto end;
    }
//    cy_hex_dump("PA", PA, PALen);
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);//EC_KEY_get0_group(ec_key);
    BIGNUM *PA_x = BN_new();
    BIGNUM *PA_y = BN_new();
    PA_x = BN_bin2bn(PA, 32, NULL);


    PA_y = BN_bin2bn(PA +32, 32, NULL);

    if((PA_x == NULL) || (PA_y == NULL))
    {
        MC_LOG_ERR("BN_bin2bn failed\n");
        ret = -1;
        goto end;
    }
    #if 1
    ret = EC_KEY_set_public_key_affine_coordinates(ec_key,PA_x, PA_y);
    if(ret != 1)
    {
        MC_LOG_ERR("EC_KEY_set_public_key_affine_coordinates failed\n");
        ret = -1;
        goto end;
    }
    #else
    if(!EC_KEY_generate_key(ec_key))
    {
        print_openssl_error();
        return -1;
    }
   
    #endif 
    EC_KEY_set_group(ec_key, group);
    EVP_PKEY *pkey  = EVP_PKEY_new();
    if(pkey == NULL)
    {
        MC_LOG_ERR("EVP_PKEY_new failed\n");
        ret = -1;
        goto end;
    }
    ret = EVP_PKEY_set1_EC_KEY(pkey, ec_key);
    //ret  = EVP_PKEY_assign_EC_KEY(pkey, ec_key);
    if(ret != 1)
    {
        MC_LOG_ERR("EVP_PKEY_set1_EC_KEY failed\n");
        ret = -1;
        goto end;
    }
   
    EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);//very important

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ctx == NULL)
    {
        MC_LOG_ERR("EVP_PKEY_CTX_new failed\n");
        ret = -1;
        goto end;
    }
    EVP_PKEY_CTX_set_ec_param_enc(ctx, NID_sm_scheme);

    #else 
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx || EVP_PKEY_paramgen_init(ctx) <= 0) {
        ERR_print_errors_fp(stderr);
        goto end;
    }
        // 设置 SM2 曲线参数
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_sm2) <= 0 ||
        EVP_PKEY_CTX_set_ec_param_enc(ctx, OPENSSL_EC_NAMED_CURVE) <= 0) {
        ERR_print_errors_fp(stderr);
        goto end;
    }
    // 生成密钥
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        ERR_print_errors_fp(stderr);
        goto end;
    }
    #endif
    ret = EVP_PKEY_encrypt_init(ctx);
    if (ret != 1)
    {
        MC_LOG_ERR("EVP_PKEY_encrypt_init failed ret is %d\n", ret);
        ERR_load_ERR_strings();
        int  err  = ERR_get_error();
        char pTmp[256] = {0};
        ERR_error_string(err, pTmp);
        ERR_print_errors_fp(stderr);
        ret = -1;
        goto end;
    }

    size_t ciphertext_len;
    if (EVP_PKEY_encrypt(ctx, NULL, &ciphertext_len, (unsigned char *)message, messageLen) <= 0) {
        handle_errors();
    }

    // 6. 分配内存并执行加密
    unsigned char *ciphertext = OPENSSL_malloc(ciphertext_len);
    if (!ciphertext) {
        handle_errors();
    }

    if (EVP_PKEY_encrypt(ctx, ciphertext, &ciphertext_len, (unsigned char *)message, messageLen) <= 0){
        handle_errors();
        ret = -1;
        goto end;
    }
    *CiphertextLen = ciphertext_len;
    memcpy(Ciphertext, ciphertext, ciphertext_len);
    ret = 0;
    
end:
    #if 1
    if(PA_x)
        BN_free(PA_x);
    if(PA_y)
        BN_free(PA_y);
    if(ctx)
        EVP_PKEY_CTX_free(ctx);
    if(ec_key)
        EC_KEY_free(ec_key);
    if(ciphertext)
        OPENSSL_free(ciphertext);
    if(group)
        EC_GROUP_free(group);
    #endif 
    return ret;
}

int opensslConvertEVPPKEY(unsigned char *dA, int dALen, EVP_PKEY **pkey)
{
    int ret = 0;
    EC_KEY *eckey = NULL;
    const EC_GROUP *group = NULL;
    BIGNUM *dA_bn = NULL;
    EC_POINT *result_PA = NULL;
    EC_POINT *G = NULL;
    dA_bn = BN_new();
    
    if(dA_bn == NULL)
    {
        MC_LOG_ERR("dA bn is NULL");
        goto end;
    }
    eckey = EC_KEY_new_by_curve_name(NID_sm2);
    if (eckey == NULL)
    {
        MC_LOG_ERR("EC_KEY_new_by_curve_name failed\n");
        ret = -1;
        goto end;
    }
   
    dA_bn = BN_bin2bn(dA, 32, NULL);
    if(dA_bn == NULL)
    {
        MC_LOG_ERR("dA bn is NULL");
        goto end;
    }

    group = EC_KEY_get0_group(eckey);
    if(group == NULL)
    {
        MC_LOG_ERR("EC_KEY_get0_group failed\n");
        ret = -1;
        goto end;
    }
     result_PA = EC_POINT_new(group);
    if(result_PA == NULL)
    {
        MC_LOG_ERR("EC_POINT_new failed\n");
        ret = -1;
        goto end;
    }
    G = EC_POINT_new(group);
    G = EC_GROUP_get0_generator(group);
    if(G == NULL)
    {
        MC_LOG_ERR("EC_GROUP_get0_generator failed\n");
        ret = -1;
        goto end;
    }
    ret = EC_POINT_mul(group, result_PA,NULL, G, dA_bn, NULL);
    if(ret != 1)
    {
        MC_LOG_ERR("mul failed\n");
        ret = -1;
        goto end;
    }
    ret = EC_KEY_set_public_key(eckey, result_PA);
    if(ret != 1)
    {
        MC_LOG_ERR("EC_KEY_set_public_key failed\n");
        ret = -1;
        goto end;
    }
    ret = EC_KEY_set_private_key(eckey, dA_bn);
    if(ret != 1)
    {
        MC_LOG_ERR("EC_KEY_set_private_key failed\n");
        ret = -1;
        goto end;
    }

    ret = EVP_PKEY_set1_EC_KEY(*pkey, eckey);
    if(ret != 1)
    {
        MC_LOG_ERR("EVP_PKEY_set1_EC_KEY failed\n");
        ret = -1;
        goto end;
    }
    ret = 0;
end:
    BN_free(dA_bn);
    EC_POINT_free(result_PA);
    
    if(eckey)
         EC_KEY_free(eckey);
    return ret;
}

int CLPKC_Decrypt(unsigned char *dA, int dALen, unsigned char *Ciphertext, int CiphertextLen, unsigned char *message, int *messageLen)
{
    int ret = 0;
    unsigned char *plain = NULL;
    size_t plainLen = CiphertextLen;
    EVP_PKEY *pkey  = NULL;
    pkey  = EVP_PKEY_new();
    if(pkey == NULL)
    {
        MC_LOG_ERR("EVP_PKEY_new failed\n");
        ret = -1;
        goto end;
    }
    ret = opensslConvertEVPPKEY(dA, dALen, &pkey);
    if(ret != 0)
    {
        MC_LOG_ERR("opensslConvertEVPPKEY failed\n");
        ret = -1;
        goto end;
    }
    EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
    EVP_PKEY_CTX *decctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (decctx == NULL)
    {
        MC_LOG_ERR("EVP_PKEY_CTX_new failed\n");
        ret = -1;
        goto end;
    }
    ret = EVP_PKEY_decrypt_init(decctx);
    if (ret != 1)
    {
        MC_LOG_ERR("EVP_PKEY_decrypt_init failed\n");
        handle_errors();
        ret = -1;
        goto end;
    }
    ret = EVP_PKEY_decrypt(decctx, NULL, &plainLen, Ciphertext, CiphertextLen);
    if (ret != 1)
    {
        MC_LOG_ERR("EVP_PKEY_decrypt len failed\n");
        handle_errors();
        ret = -1;
        goto end;
    }
    plain = OPENSSL_malloc(plainLen);
    if (plain == NULL)
    {
        MC_LOG_ERR("plain malloc failed\n");
        ret = -1;
        goto end;
    }
    ret = EVP_PKEY_decrypt(decctx, plain, &plainLen, Ciphertext, CiphertextLen);
    if (ret != 1)
    {
        MC_LOG_ERR("EVP_PKEY_decrypt failed\n");
        handle_errors();
        ret = -1;
        goto end;
    }
    handle_errors();
    *messageLen = (int)plainLen;
    memcpy(message, plain, plainLen);
    ret = 0;
end:
    OPENSSL_free(plain);
    EVP_PKEY_CTX_free(decctx);
    EVP_PKEY_free(pkey);
    return ret;
}