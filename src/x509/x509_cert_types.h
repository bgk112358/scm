// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//
#ifndef SVKD_BUILD_X509_CERT_TYPES_H
#define SVKD_BUILD_X509_CERT_TYPES_H

#include <string>
#include <array>

namespace cyber {

struct CertAttribute {
    CertAttribute();
    CertAttribute(const CertAttribute&);
    CertAttribute(CertAttribute&&) noexcept ;
    ~CertAttribute();

    // 国家 C，长度不能超过 2 字节
    std::string country;
    // 省份或州 ST
    std::string state_or_province_name;
    // 城市 L
    std::string locality;
    // 单位 O
    std::string organization;
    // 部门 OU
    std::string organization_unit;
    // 序列号 SN
    std::string serial_number;
    // 通用名称 CN
    std::string common_name;
    // 域名组件 DC
    std::array<std::string, 3> domain_components;
    // 挑战应答码
    std::string challengePassword;
    // 主题替代名称
    std::string subject_alt_name;
};

}


#endif //SVKD_BUILD_X509_CERT_TYPES_H
