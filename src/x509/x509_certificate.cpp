// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//

#include "x509_certificate.h"
#include <openssl/pem.h>
#include "util/util.h"
#include "crypto/base64.h"
#include "common/config.h"

namespace cyber {

X509Certificate::X509Certificate(X509 *x509) : x509_(x509) { }

X509Certificate::~X509Certificate() {
    if (x509_ )  X509_free(x509_);
}

X509Certificate::CertificateFormat GetCertificateFormat(const std::string& cert_buffer) {
    std::string pem_prefix = "-----BEGIN CERTIFICATE-----";
    std::string b64_prefix = "MI";

    if (cert_buffer.compare(0, pem_prefix.length(), pem_prefix) == 0) {
        return X509Certificate::FORMAT_PEM_CERT;
    }
    if (cert_buffer.compare(0, b64_prefix.length(), b64_prefix) == 0) {
        return X509Certificate::FORMAT_BASE64_CERT;
    }
    return X509Certificate::FORMAT_DER_CERT;
}

std::unique_ptr<X509Certificate> X509Certificate::CreateFromX509(X509 *x509) {
    return x509 ? std::unique_ptr<X509Certificate>(new X509Certificate(x509)) : nullptr;
}

std::unique_ptr<X509Certificate> X509Certificate::CreateFromBase64String(
        const std::string &base64_string) {
    std::vector<unsigned char> bytes = Base64Decode(base64_string);
    return CreateFromDerString(bytes.data(), bytes.size());
}

std::unique_ptr<X509Certificate> X509Certificate::CreateFromDerString(
        const unsigned char *ucDerStr,
        unsigned int uiDerLen) {
    auto *in = ucDerStr;
    X509 *x509 = d2i_X509(nullptr, &in, (long )uiDerLen);
    return CreateFromX509(x509);
}

std::unique_ptr<X509Certificate> X509Certificate::CreateFromPemString(
        const std::string& pem_string) {
    const auto * start =
            reinterpret_cast<const unsigned char*>(pem_string.data());
    BIO *bio = BIO_new_mem_buf(start, (int)pem_string.length());
    if (!bio) {
        return nullptr;
    }
    X509 *x509 = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return CreateFromX509(x509);
}

std::unique_ptr<X509Certificate> X509Certificate::CreateFromBytes(
        const std::string &bytes)
{
    std::unique_ptr<X509Certificate> result(new X509Certificate());
    CertificateFormat format = GetCertificateFormat(bytes);
    switch (format) {
        case FORMAT_BASE64_CERT:
            result = CreateFromBase64String(bytes);
            break;
        case FORMAT_DER_CERT:
            result = CreateFromDerString((const unsigned char *)bytes.data(),
                                         bytes.size());
            break;
        case FORMAT_PEM_CERT:
            result = CreateFromPemString(bytes);
            break;
    }
    return result;
}

bool X509Certificate::GetVersion(std::string *version) {
    if (x509_ == nullptr || version == nullptr) {
        return false;
    }
    long val = X509_get_version(x509_);
    *version = std::to_string(val);
    return true;
}

bool X509Certificate::GetSerialNumber(std::string *serialNumber) {
    ASN1_INTEGER *serial;
    BIGNUM *bn;
    char *buffer;
    if (x509_ == nullptr || serialNumber == nullptr) {
        return false;
    }
    if (!(serial = X509_get_serialNumber(x509_))) {
        return false;
    }
    if (!(bn = ASN1_INTEGER_to_BN(serial, nullptr))) {
        return false;
    }
    buffer = BN_bn2hex(bn);
    serialNumber->assign(buffer, strlen(buffer));
    BN_free(bn);
    OPENSSL_free(buffer);
    return true;
}

bool X509Certificate::GetSignatureAlgorithm(int *alg) {
    if (x509_ == nullptr || alg == nullptr) {
        return false;
    }
    *alg = X509_get_signature_nid(x509_);
    return true;
}

bool X509Certificate::GetIssuerName(std::string *issuer) {
    X509_NAME *name;
    char *str;
    if (x509_ == nullptr || issuer == nullptr) {
        return false;
    }
    if (!(name = X509_get_issuer_name(x509_))) {
        return false;
    }
    if (!(str = X509_NAME_oneline(name, nullptr, 0))) {
        return false;
    }
    issuer->assign(str, strlen(str));
    OPENSSL_free(str);
    return true;
}

bool X509Certificate::GetSubjectName(std::string *subject) {
    X509_NAME *name;
    char *str;
    if (x509_ == nullptr || subject == nullptr) {
        return false;
    }
    if (!(name = X509_get_subject_name(x509_))) {
        return false;
    }
    if (!(str = X509_NAME_oneline(name, nullptr, 0))) {
        return false;
    }
    subject->assign(str, strlen(str));
    OPENSSL_free(str);
    return true;
}

bool X509Certificate::GetSubjectSerialNumber(std::string *subject) {
    X509_NAME *name;
    char *str;
    if (x509_ == nullptr || subject == nullptr) {
        return false;
    }
    if (!(name = X509_get_subject_name(x509_))) {
        return false;
    }
    int index = X509_NAME_get_index_by_NID(name, NID_serialNumber, -1);
    X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, index);
    if (entry == nullptr) {
        return false;
    }
    ASN1_STRING *entry_data = X509_NAME_ENTRY_get_data(entry);
    if (entry_data == nullptr) {
        return false;
    }
    str = (char*) ASN1_STRING_get0_data(entry_data);
    if (str == nullptr) {
        return false;
    }
    subject->assign(str, strlen(str));
    return true;
}


bool X509Certificate::GetEffectiveTime(std::string *effective_time) {
    const ASN1_TIME *notBefore;
    if (x509_ == nullptr || effective_time == nullptr) {
        return false;
    }
    if (!(notBefore = X509_get0_notBefore(x509_))) {
        return false;
    }
    effective_time->assign(notBefore->data, notBefore->data + notBefore->length);
    return true;
}

bool X509Certificate::GetExpirationTime(std::string *expiration_time) {
    const ASN1_TIME *notAfter;
    if (x509_ == nullptr || expiration_time == nullptr) {
        return false;
    }
    if (!(notAfter = X509_get0_notAfter(x509_))) {
        return false;
    }
    expiration_time->assign(notAfter->data, notAfter->data + notAfter->length);
    return true;
}

bool X509Certificate::GetSubjectPublicKeyInfo(
        size_t *size_bits,
        std::string *key_type) {
    if (x509_ == nullptr || size_bits == nullptr || key_type == nullptr) {
        return false;
    }
    const EVP_PKEY *pkey = X509_get0_pubkey(x509_);
    if (pkey == nullptr) {
        return false;
    }
    *size_bits = EVP_PKEY_bits(pkey);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    int type = EVP_PKEY_get_base_id(pkey);
#else
    int type = EVP_PKEY_id(pkey);
#endif
    switch (type) {
        case EVP_PKEY_RSA:
            *key_type = "RSA" + std::to_string(*size_bits);
            break;
        case EVP_PKEY_EC:
            *key_type = "ECC";
            break;
        case EVP_PKEY_SM2:
            *key_type = "SM2";
            break;
        case EVP_PKEY_ED25519:
            *key_type = "ED25519";
            break;
        default:
            *key_type = "Unknown";
            break;
    }
    return true;
}

bool X509Certificate::GetSubjectPublicKey(
        std::vector<unsigned char> *public_key) {
    EVP_PKEY *pubkey;
    unsigned char *val = nullptr;
    if (x509_ == nullptr || public_key == nullptr) {
        return false;
    }
    if (!(pubkey = X509_get0_pubkey(x509_))) {
        return false;
    }
    int len = i2d_PUBKEY(pubkey, &val);
    if (len < 1) {
        return false;
    }
    public_key->assign(val, val + len);
    OPENSSL_free(val);
    return true;
}

bool X509Certificate::GetAuthorityKeyIdentify(std::string *identify) {
    X509_EXTENSION *extension;
    ASN1_OCTET_STRING *data;
    int loc;
    char *buffer;
    if (x509_ == nullptr || identify == nullptr) {
        return false;
    }
    loc = X509_get_ext_by_NID(x509_, NID_authority_key_identifier, -1);
    if (!(extension = X509_get_ext(x509_, loc))) {
        return false;
    }
    if (!(data = X509_EXTENSION_get_data(extension))) {
        return false;
    }
    buffer = OPENSSL_buf2hexstr(data->data, data->length);
    if (buffer == nullptr) {
        return false;
    }
    identify->clear();
    identify->assign(buffer, strlen(buffer));
    OPENSSL_free(buffer);
    return true;
}

bool X509Certificate::GetSubjectKeyIdentify(std::string *identify) {
    X509_EXTENSION *extension;
    ASN1_OCTET_STRING *data;
    int loc;
    char *buffer;
    if (x509_ == nullptr || identify == nullptr) {
        return false;
    }
    loc = X509_get_ext_by_NID(x509_, NID_subject_key_identifier, -1);
    if (!(extension = X509_get_ext(x509_, loc))) {
        return false;
    }
    if (!(data = X509_EXTENSION_get_data(extension))) {
        return false;
    }
    buffer = OPENSSL_buf2hexstr(data->data, data->length);
    if (buffer == nullptr) {
        return false;
    }
    identify->assign(buffer, strlen(buffer));
    OPENSSL_free(buffer);
    return true;
}

bool X509Certificate::GetBasicConstraints(bool *constraints) {
    BASIC_CONSTRAINTS *basic_constraints;
    if (x509_ == nullptr || constraints == nullptr) {
        return false;
    }
    basic_constraints = (BASIC_CONSTRAINTS *)X509_get_ext_d2i(x509_,
                                                      NID_basic_constraints,
                                                      nullptr, nullptr);
    if (basic_constraints == nullptr) {
        *constraints = false;
    } else {
        *constraints = basic_constraints->ca;
    }
    BASIC_CONSTRAINTS_free(basic_constraints);
    return true;
}

bool X509Certificate::GetCrlDistributionPoints(std::string *crl_points) {
    bool rv = false;
    int num, gtype = 0;
    STACK_OF(DIST_POINT)* crldp;
    DIST_POINT *dp;
    GENERAL_NAMES *gens;
    GENERAL_NAME  *gen;
    if (x509_ == nullptr || crl_points == nullptr) {
        return false;
    }
    crldp = static_cast<stack_st_DIST_POINT *>(
            X509_get_ext_d2i(x509_,
                             NID_crl_distribution_points,
                             nullptr,
                             nullptr));
    if (crldp == nullptr) {
        return false;
    }
    if (sk_DIST_POINT_num(crldp) < 1) {
        goto cleanup;
    }
    dp = sk_DIST_POINT_value(crldp, 0);
    if (dp == nullptr || dp->distpoint == nullptr) {
        return false;
    }
    gens = dp->distpoint->name.fullname;
    if (gens == nullptr) {
        return false;
    }
    num = sk_GENERAL_NAME_num(gens);
    for (int i = 0; i < num; ++i) {
        if ((gen = sk_GENERAL_NAME_value(gens, i))) {
            auto *asn1_str = (ASN1_STRING *)GENERAL_NAME_get0_value(gen, &gtype);
            if (gtype == GEN_URI && asn1_str) {
                crl_points->assign(
                        reinterpret_cast<const char *>(asn1_str->data),
                        asn1_str->length);
                rv = true;
                goto cleanup;
            }
        }
    }
cleanup:
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    return rv;
}


bool X509Certificate::GetKeyUsage(X509Certificate::KeyUsage *keyUsage) {
    uint32_t val;
    if (x509_ == nullptr || keyUsage == nullptr) {
        return false;
    }
    if (!(val = X509_get_key_usage(x509_))) {
        return false;
    }
    int value = 0;
    if ((val & KU_DIGITAL_SIGNATURE) == KU_DIGITAL_SIGNATURE) {
        value |= kDigitalSignature;
    }
    if ((val & KU_NON_REPUDIATION) == KU_NON_REPUDIATION) {
        value |= kNonRepudiation;
    }
    if ((val & KU_KEY_ENCIPHERMENT) == KU_KEY_ENCIPHERMENT) {
        value |= kKeyEncipherment;
    }
    if ((val & KU_DATA_ENCIPHERMENT) == KU_DATA_ENCIPHERMENT) {
        value |= kDataEncipherment;
    }
    if ((val & KU_KEY_AGREEMENT) == KU_KEY_AGREEMENT) {
        value |= kKeyAgreement;
    }
    if ((val & KU_KEY_CERT_SIGN) == KU_KEY_CERT_SIGN) {
        value |= kKeyCertSign;
    }
    if ((val & KU_CRL_SIGN) == KU_CRL_SIGN) {
        value |= kCRLSign;
    }
    if ((val & KU_ENCIPHER_ONLY) == KU_ENCIPHER_ONLY) {
        value |= kEncipherOnly;
    }
    if ((val & KU_DECIPHER_ONLY) == KU_DECIPHER_ONLY) {
        value |= kDecipherOnly;
    }
    *keyUsage = (KeyUsage)value;
    return true;
}

bool X509Certificate::GetKeyUsage(std::string *keyUsage) {
    uint32_t val;
    if (x509_ == nullptr || keyUsage == nullptr) {
        return false;
    }
    if (!(val = X509_get_key_usage(x509_))) {
        return false;
    }
    *keyUsage = std::to_string(val);
    return true;
}

bool X509Certificate::GetExtendedKeyUsage(ExtendedKeyUsage *extendedKeyUsage) {
    uint32_t val;
    if (x509_ == nullptr || extendedKeyUsage == nullptr) {
        return false;
    }
    if (!(val = X509_get_extended_key_usage(x509_))) {
        return false;
    }
    int value = 0;
    if ((val & XKU_SSL_SERVER) == XKU_SSL_SERVER) {
        value |= kServerAuth;
    }
    if ((val & XKU_SSL_CLIENT) == XKU_SSL_CLIENT) {
        value |= kClientAuth;
    }
    if ((val & XKU_SMIME) == XKU_SMIME) {
        value |= kSMIME;
    }
    if ((val & XKU_CODE_SIGN) == XKU_CODE_SIGN) {
        value |= kCodeSigning;
    }
    if ((val & XKU_SGC) == XKU_SGC) {
        value |= kSGC;
    }
    if ((val & XKU_TIMESTAMP) == XKU_TIMESTAMP) {
        value |= kTimeStamping;
    }
    if ((val & XKU_OCSP_SIGN) == XKU_OCSP_SIGN) {
        value |= kOcspSigning;
    }
    *extendedKeyUsage = (ExtendedKeyUsage)value;
    return true;
}


bool X509Certificate::HasExpired() const {
    int rv;
    ASN1_TIME *notAfter;
    if (x509_ == nullptr) {
        return false;
    }
    notAfter = X509_getm_notAfter(x509_);
    rv = X509_cmp_current_time(notAfter);
    if (rv <= 0) {
        return true;
    }
    return false;
}

bool X509Certificate::WillExpired(int days) const {
    int rv;
    ASN1_TIME *notAfter, *notExpired;
    if (x509_ == nullptr) {
        return false;
    }
    notAfter = X509_getm_notAfter(x509_);
    notExpired = ASN1_TIME_new();
    if (notExpired == nullptr) {
        return false;
    }
    ASN1_TIME_set(notExpired, time(nullptr) - days * 24 * 60 * 60);
    rv = ASN1_TIME_compare(notAfter, notExpired);
    ASN1_TIME_free(notExpired);
    if (rv <= 0) {
        return true;
    }
    return false;
}

bool X509Certificate::GetPEMEncode(
        std::string & pem_encoded) const {
    int rv;
    BIO *bio;
    if (x509_ == nullptr) {
        return false;
    }
    if (!(bio = BIO_new(BIO_s_mem()))) {
        return false;
    }
    rv = PEM_write_bio_X509(bio, x509_);
    if (rv != 1) {
        BIO_free(bio);
        return false;
    }
    OpensslUtils::ReadBio(bio, pem_encoded);
    BIO_free(bio);
    return true;
}

void X509Certificate::Print() {
    if (x509_ == nullptr) {
        fprintf(stdout, "The Certificate is nullptr.");
    } else {
        X509_print_fp(stdout, x509_);
    }
}

bool X509Certificate::GetPEMEncodeFromDER(const std::string &der_encode,
                                          std::string &pem_encode) {
    int rv;
    auto *in = (const unsigned char *)der_encode.data();
    X509 *x509 = d2i_X509(nullptr, &in, (long)der_encode.size());
    if (x509 == nullptr) {
        return false;
    }
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) {
        goto cleanup;
    }
    rv = PEM_write_bio_X509(bio, x509);
    if (rv != 1) {
        goto cleanup;
    }
    OpensslUtils::ReadBio(bio, pem_encode);
cleanup:
    BIO_free(bio);
    X509_free(x509);
    return true;
}


}

