// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef SVKD_BUILD_X509_REQUEST_H
#define SVKD_BUILD_X509_REQUEST_H

#include <string>
#include <utility>
#include <vector>
#include <openssl/evp.h>
#include <openssl/engine.h>

namespace cyber {

class X509Request {
public:
    ~X509Request();

    X509Request();

    // 算法名
    void SetAlgorithm(const std::string & algorithm);

    // 国家 C，长度不能超过 2 字节
    void SetCountry(const std::string & country) {
        country_ = country;
    }
    // 省份或州 ST
    void SetStateOrProvinceName(const std::string & state_or_province_name) {
        state_or_province_name_ = state_or_province_name;
    }
    // 城市 L
    void SetLocality(const std::string & locality) {
        locality_ = locality;
    }
    // 单位 O
    void SetOrganization(const std::string & organization) {
        organization_ = organization;
    }
    // 部门 OU
    void SetOrganizationUnit(const std::string & organization_unit) {
        organization_unit_ = organization_unit;
    }
    // 序列号 SN
    void SetSerialNumber(const std::string & serial_number) {
        serial_number_ = serial_number;
    }
    // 通用名称 CN
    void SetCommonName(const std::string & common_name) {
        common_name_ = common_name;
    }
    // 域名组件 DC
    void SetDomainComponents1(const std::string & domain_components1) {
        domain_components1_ = domain_components1;
    }
    void SetDomainComponents2(const std::string & domain_components2) {
        domain_components2_ = domain_components2;
    }
    void SetDomainComponents3(const std::string & domain_components3) {
        domain_components3_ = domain_components3;
    }
    // 挑战应答码
    void SetChallengePassword(const std::string & challengePassword) {
        challengePassword_ = challengePassword;
    }
    // 主题替代名称
    void SetSubjectAltName(const std::string & subject_alt_name) {
        subject_alt_name_ = subject_alt_name;
    }

    // Private Key
    void SetPrivateKey(std::vector<unsigned char>& privateKey) {
        vPrivateKey_ = privateKey;
    }

    // Method
    bool BuildRequest();
    bool BuildAttribute();
    bool BuildPublicKey();
    bool BuildSignature();

    // Export
    bool GetPemEncode(std::string &pem_encode) const;
    bool GetDerEncode(std::vector<unsigned char> *der_encode) const;

public:
    // Attribute Info
    std::string algorithm_ = "ECC";
    std::string country_;
    std::string state_or_province_name_;
    std::string locality_;
    std::string organization_;
    std::string organization_unit_;
    std::string serial_number_;
    std::string common_name_;
    std::string domain_components1_;
    std::string domain_components2_;
    std::string domain_components3_;
    std::string challengePassword_;
    std::string subject_alt_name_;
    // Private Key
    std::vector<unsigned char> vPrivateKey_;
    private:
    // X509 Request
    std::string sHashAlgorithm = "SHA256";
    int sign_nid   = 0;
    X509_REQ *x509_req_ = nullptr;
};

}


#endif //SVKD_BUILD_X509_REQUEST_H
