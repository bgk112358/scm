// 
// Create by kong
// Copyright 2023 China Automotive Research Software Evaluating Co., Ltd.
// Error message reference: GMT-0019-2012
//
#ifndef SVKD_BUILD_STATUS_UTIL_H
#define SVKD_BUILD_STATUS_UTIL_H

#include <string>

#define OPENSSL_SUCCESS 1
#define OPENSSL_FAILURE 0

namespace cyber {
namespace error {
enum Code {
    Ok			             = 0x00000000,  // 成功
    UnknownErr		         = 0x02000001,  // 异常错误
    NotSupportYetErr         = 0x02000002,  // 不支持的服务
    FileErr		             = 0x02000003,  // 文件操作错误
    ProviderTypeErr	         = 0x02000004,  // 服务提供者参数类型错误
    LoadProviderErr	         = 0x02000005,  // 导入服务提供者接口错误
    LoadDevMngApiErr         = 0x02000006,  // 导入设备管理接口错误
    AlgoTypeErr		         = 0x02000007,  // 算法类型错误
    NameLenErr		         = 0x02000008,  // 名称长度错误
    KeyUsageErr		         = 0x02000009,  // 密钥用途错误
    ModulusLenErr	         = 0x02000010,  // 模的长度错误
    NotInitializeErr         = 0x02000011,  // 未初始化
    ObjErr		             = 0x02000012,  // 对象错误
    FileNotFoundErr	         = 0x02000013,  // 文件未发现
    MemoryErr		         = 0x02000100,  // 内存错误
    TimeoutErr		         = 0x02000101,  // 超时
    ConnectErr               = 0x02000102,  // 连接失败
    ResolveHostErr	         = 0x02000103,  // 主机名解析失败
    IndataLenErr	         = 0x02000200,  // 输入数据长度错误
    IndataErr		         = 0x02000201,  // 输入数据错误
    GenRandErr		         = 0x02000300,  // 生成随机数错误
    HashObjErr		         = 0x02000301,  // HASH 对象错误
    HashErr		             = 0x02000302,  // HASH 运算错误
    GenKeyErr	             = 0x02000303,  // 产生密钥对错误
    RsaModulusLenErr         = 0x02000304,  // RSA 密钥模长错误
    EncErr		             = 0x02000306,  // 加密错误
    DecErr		             = 0x02000307,  // 解密错误
    HashNotEqualErr	         = 0x02000308,  // HASH 值不相等
    KeyNotFoundErr	         = 0x02000309,  // 密钥未发现
    CertNotFoundErr	         = 0x02000310,  // 证书未发现
    NotExportErr	         = 0x02000311,  // 对象未导出
    CertRevokedErr	         = 0x02000316,  // 证书被吊销
    CertNotYetValidErr       = 0x02000317,  // 证书未生效
    CertHasExpiredErr        = 0x02000318,  // 证书已过期
    CertVerifyErr	         = 0x02000319,  // 证书验证错误
    CertEncodeErr	         = 0x02000320,  // 证书编码错误
    GenCertErr	             = 0x02000321,  // 产生证书错误
    GetCertInfoErr	         = 0x02000322,  // 获取证书信息错误
    CertPublicKeyNotMatchErr = 0x02000323,  // 证书公钥不匹配
    DecryptPadErr	         = 0x02000400,  // 解密时做补丁错误
    MacLenErr		         = 0x02000401,  // MAC 长度错误
    KeyInfoTypeErr	         = 0x02000402,  // 密钥类型错误
    NotLogin		         = 0x02000403,  // 没有进行登录认证
    KeyErr	                 = 0x02000404,  // 密钥错误
    KeyEncodeErr	         = 0x02000405,  // 密钥编码错误
    SignErr	                 = 0x02000406,  // 签名错误
    VerifyErr	             = 0x02000407,  // 验证签名错误
    Pkcs7EncodeErr           = 0x02000408,  // Pkcs7 编码失败
    ScepStatusErr            = 0x02000409,  // Scep 状态异常
    AttributesVerifyErr      = 0x0200040A,  // 属性校验失败
    MessageVerifyErr         = 0x0200040B,  // 报文校验失败
};

}

// Status Util
namespace util {

class Status {
public:
    // Creates an OK status
    Status();

    // Make a Status from the specified error and message.
    Status(int code, const std::string& error_message);

    Status(const Status& other);
    Status& operator=(const Status& other);

    bool ok() const {
        return code_ == error::Ok;
    }

    bool notok() const  {
        return code_ != error::Ok;
    }

    int code() const {
        return code_;
    }

    std::string message() const {
        return message_;
    }

private:
    int code_;
    std::string message_;

};

inline Status OkStatus()   { return { error::Code::Ok, ""}; }
inline Status FailStatus() { return { error::Code::UnknownErr, ""}; }
inline Status FailMemory() { return { error::Code::MemoryErr, "Memory error"}; }
inline Status FailArg(const std::string &msg = "") { return { error::Code::IndataErr, msg}; }
inline Status FailStatus(int code, const std::string &msg = "") { return { code, msg}; }

}
}


#endif //SVKD_BUILD_STATUS_UTIL_H
