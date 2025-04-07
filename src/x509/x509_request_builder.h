// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef SVKD_BUILD_X509_REQUEST_BUILDER_H
#define SVKD_BUILD_X509_REQUEST_BUILDER_H

#include <string>
#include <memory>
#include "x509_request.h"
#include "util/log_utils.h"

namespace cyber {

class X509RequestBuilder {
public:
    X509RequestBuilder() {
        x509Request_ = std::unique_ptr<X509Request>(new X509Request());
    }

    // Algorithm
    X509RequestBuilder& SetAlgorithm(const std::string & algorithm) {
        x509Request_->SetAlgorithm(algorithm);
        return *this;
    }
    // Attribute Info
    X509RequestBuilder& SetCountry(const std::string & country) {
        x509Request_->SetCountry(country);
        return *this;
    }
    X509RequestBuilder& SetStateOrProvinceName(const std::string & state_or_province_name) {
        x509Request_->SetStateOrProvinceName(state_or_province_name);
        return *this;
    }
    X509RequestBuilder& SetLocality(const std::string & locality) {
        x509Request_->SetLocality(locality);
        return *this;
    }
    X509RequestBuilder& SetOrganization(const std::string & organization) {
        x509Request_->SetOrganization(organization);
        return *this;
    }
    X509RequestBuilder& SetOrganizationUnit(const std::string & organization_unit) {
        x509Request_->SetOrganizationUnit(organization_unit);
        return *this;
    }
    X509RequestBuilder& SetSerialNumber(const std::string & serial_number) {
        x509Request_->SetSerialNumber(serial_number);
        return *this;
    }
    X509RequestBuilder& SetCommonName(const std::string & common_name) {
        x509Request_->SetCommonName(common_name);
        return *this;
    }
    X509RequestBuilder& SetDomainComponents1(const std::string & domain_components1) {
        x509Request_->SetDomainComponents1(domain_components1);
        return *this;
    }
    X509RequestBuilder& SetDomainComponents2(const std::string & domain_components2) {
        x509Request_->SetDomainComponents2(domain_components2);
        return *this;
    }
    X509RequestBuilder& SetDomainComponents3(const std::string & domain_components3) {
        x509Request_->SetDomainComponents3(domain_components3);
        return *this;
    }
    X509RequestBuilder& SetChallengePassword(const std::string & challengePassword) {
        x509Request_->SetChallengePassword(challengePassword);
        return *this;
    }
    X509RequestBuilder& SetSubjectAltName(const std::string & subject_alt_name) {
        x509Request_->SetSubjectAltName(subject_alt_name);
        return *this;
    }
    // Private Key
    X509RequestBuilder& SetDerPrivateKey(std::vector<unsigned char>& privateKey) {
        x509Request_->SetPrivateKey(privateKey);
        return *this;
    }
    std::unique_ptr<X509Request> build() {
        x509Request_->BuildRequest();
        x509Request_->BuildAttribute();
        if (!x509Request_->BuildPublicKey()) {
            LOGM(ERROR, "x509Request BuildPublicKey fail");
            return nullptr;
        }
        if (!x509Request_->BuildSignature()) {
            LOGM(ERROR, "x509Request BuildSignature fail");
            return nullptr;
        }
        return std::move(x509Request_);
    }
private:
    std::unique_ptr<X509Request> x509Request_;
};
}

#endif //SVKD_BUILD_X509_REQUEST_BUILDER_H
