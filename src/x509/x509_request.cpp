// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//

#include "x509_request.h"
#include <openssl/evp.h>
#include "common/config.h"
static const char *engine_id = "cyber_security";
#include <openssl/obj_mac.h>
#include "util/util.h"
#include "crypto/asymmetric_signer.h"
#include "crypto/generators/rsa_keypair.h"


namespace cyber
{ 
X509Request::X509Request() {
    Openssl_error_clear();
}

X509Request::~X509Request()
{
    if (x509_req_ != nullptr)
        X509_REQ_free(x509_req_);
}

void X509Request::SetAlgorithm(const std::string &algorithm) {
    if (StringUtils::ContainIgnoreCaseWith(algorithm, "RSA")) {
        sign_nid   = NID_sha256WithRSAEncryption;
        sHashAlgorithm = "SHA256";
    } else if (StringUtils::ContainIgnoreCaseWith(algorithm, "EC")) {
        sign_nid   = NID_ecdsa_with_SHA256;
        sHashAlgorithm = "SHA256";
    } else if (StringUtils::ContainIgnoreCaseWith(algorithm, "ED25519")) {
        sign_nid = NID_ED25519;
        sHashAlgorithm = "SHA256";
    } else if (StringUtils::ContainIgnoreCaseWith(algorithm, "SM2")) {
        sign_nid = NID_SM2_with_SM3;
        sHashAlgorithm = "SM3";
    }
    algorithm_ = algorithm;
}

// Reference link:
// https://www.openssl.org/docs/man3.0/man3/X509_NAME_add_entry_by_NID.html
bool X509Request::BuildAttribute() {
    X509_NAME *name;
    X509_EXTENSION *ext;
    STACK_OF(X509_EXTENSION) *exts;
    if (x509_req_ == nullptr) {
        return false;
    }
    if (!(name = X509_REQ_get_subject_name(x509_req_))) {
        return false;
    }
    // Add X509 REQ version.
    if (!(X509_REQ_set_version(x509_req_, 0))) {
        return false;
    }
    // Add X509 NAME Information.
    if (!country_.empty()) {
        X509_NAME_add_entry_by_NID(
                name, NID_countryName, MBSTRING_ASC,
                (const unsigned char *)country_.c_str(),
                -1, -1, 0);
    }
    if (!state_or_province_name_.empty()) {
        X509_NAME_add_entry_by_NID(
                name, NID_stateOrProvinceName, V_ASN1_UTF8STRING,
                (const unsigned char *)state_or_province_name_.c_str(),
                -1, -1, 0);
    }
    if (!locality_.empty()) {
        X509_NAME_add_entry_by_NID(
                name, NID_localityName, V_ASN1_UTF8STRING,
                (const unsigned char *)locality_.c_str(), -1, -1, 0);
    }
    if (!organization_.empty()) {
        X509_NAME_add_entry_by_NID(
                name, NID_organizationName, V_ASN1_UTF8STRING,
                (const unsigned char *)organization_.c_str(),
                -1, -1, 0);
    }
    if (!organization_unit_.empty()) {
        X509_NAME_add_entry_by_NID(
                name, NID_organizationName, V_ASN1_UTF8STRING,
                (const unsigned char *)organization_unit_.c_str(),
                -1, -1, 0);
    }
    if (!serial_number_.empty()) {
        X509_NAME_add_entry_by_NID(
                name, NID_serialNumber, V_ASN1_UTF8STRING,
                (unsigned char *)serial_number_.c_str(),
                -1, -1, 0);
    }
    if (!common_name_.empty()) {
        X509_NAME_add_entry_by_NID(
                name, NID_commonName, V_ASN1_UTF8STRING,
                (unsigned char *)common_name_.c_str(),
                -1, -1, 0);
    }
    if (!domain_components1_.empty()) {
        X509_NAME_add_entry_by_NID(
                name, NID_domainComponent, V_ASN1_UTF8STRING,
                (unsigned char *) domain_components1_.c_str(),
                -1, -1, 0);
    }
    if (!domain_components2_.empty()) {
        X509_NAME_add_entry_by_NID(
                name, NID_domainComponent, V_ASN1_UTF8STRING,
                (unsigned char *)domain_components2_.c_str(),
                -1, -1, 0);
    }
    if (!domain_components3_.empty()) {
        X509_NAME_add_entry_by_NID(
                name, NID_domainComponent, V_ASN1_UTF8STRING,
                (unsigned char *)domain_components3_.c_str(),
                -1, -1, 0);
    }
    if (!challengePassword_.empty()) {
        X509_REQ_add1_attr_by_NID(
                x509_req_, NID_pkcs9_challengePassword, V_ASN1_UTF8STRING,
                (const unsigned char *)challengePassword_.c_str(), -1);
    }
    if (!subject_alt_name_.empty()) {
        if (!(exts = sk_X509_EXTENSION_new_null())) {
            return false;
        }
        ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name,
                                  subject_alt_name_.c_str());
        sk_X509_EXTENSION_push(exts, ext);
        X509_REQ_add_extensions(x509_req_, exts);
    }
    return true;
}

bool X509Request::BuildPublicKey() {
    if (vPrivateKey_.empty()) {
        return false;
    }
    // It doesn't matter what algorithm is it.
    std::shared_ptr<IKeyPair> iKeyPair = std::make_shared<RsaKeyPair>();
    if (!iKeyPair->ImportDerPrivateKey(vPrivateKey_) &&
        !iKeyPair->ImportDerPublicKey(vPrivateKey_)) {
        return false;
    }
    if (!X509_REQ_set_pubkey(x509_req_, iKeyPair->GetPrivateKey())) {
        return false;
    }
    return true;
}

bool X509Request::BuildSignature() 
{
    bool result = false;
    ASN1_BIT_STRING *bitString;
    X509_ALGOR *algor;
    ASN1_OBJECT *object;
    std::shared_ptr<ISigner>  iSigner;
    std::shared_ptr<IKeyPair> iKeyPair = std::make_shared<RsaKeyPair>();
    std::vector<unsigned char> vMessage, vSignature;
    unsigned char *tbs = nullptr;
    size_t len;
    if (vPrivateKey_.empty()) {
        goto cleanup;
    }
    len = i2d_re_X509_REQ_tbs(x509_req_, &tbs);
    if (len <= 0 || tbs == nullptr) {
        goto cleanup;
    }
    if (!iKeyPair->ImportDerPrivateKey(vPrivateKey_) &&
        !iKeyPair->ImportDerPublicKey(vPrivateKey_)) {
        return false;
    }
    iSigner = AsymmetricSigner::CreateSigner(iKeyPair->GetAlgorithmName());
    vMessage.assign(tbs, tbs + len);
    iSigner->MakeSignature(iKeyPair.get(), sHashAlgorithm, vMessage, vSignature);
    // Setting Signature Algorithm
    if (!(algor = X509_ALGOR_new())) {
        return false;
    }
    object = OBJ_nid2obj(sign_nid);
    if (X509_ALGOR_set0(algor, object, V_ASN1_UNDEF, nullptr) != 1 ||
        X509_REQ_set1_signature_algo(x509_req_, algor) != 1) {
        return false;
    }
    X509_ALGOR_free(algor);
    // Setting Signature
    bitString = ASN1_BIT_STRING_new();
    if (!bitString) {
        goto cleanup;
    }
    ASN1_BIT_STRING_set(bitString, vSignature.data(),
                        (int)vSignature.size());
    bitString->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    bitString->flags |= ASN1_STRING_FLAG_BITS_LEFT;
    X509_REQ_set0_signature(x509_req_, bitString);
    result = true;
cleanup:
    OPENSSL_free(tbs);
    return result;
}

bool X509Request::BuildRequest() {
    x509_req_ = X509_REQ_new();
    if (x509_req_ == nullptr) {
        return false;
    }
    return true;
}

bool X509Request::GetPemEncode(std::string &pem_encode) const {
    BIO *bio;
    if (x509_req_ == nullptr) {
        return false;
    }
    if (!(bio = BIO_new(BIO_s_mem()))) {
        LOGM_OPENSSL_ERRORS();
        return false;
    }
    if (PEM_write_bio_X509_REQ(bio, x509_req_) != 1) {
        LOGM_OPENSSL_ERRORS();
        return false;
    }
    OpensslUtils::ReadBio(bio, pem_encode);
    return true;
}

bool X509Request::GetDerEncode(std::vector<unsigned char> *der_encode) const {
    BIO *bio;
    if (x509_req_ == nullptr || der_encode == nullptr) {
        return false;
    }
    if (!(bio = BIO_new(BIO_s_mem()))) {
        LOGM_OPENSSL_ERRORS();
        return false;
    }
    if (i2d_X509_REQ_bio(bio, x509_req_) != 1) {
        BIO_free(bio);
        LOGM_OPENSSL_ERRORS();
        return false;
    }
    std::string buffer;
    OpensslUtils::ReadBio(bio, buffer);
    (*der_encode).assign(buffer.data(), buffer.data() + buffer.size());
    BIO_free(bio);
    return true;
}
}