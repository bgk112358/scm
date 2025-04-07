// 
// Create by kong
// Copyright China Automotive Research Software Evaluating Co., Ltd.
//
#ifndef SVKD_BUILD_X509_CERTIFICATE_H
#define SVKD_BUILD_X509_CERTIFICATE_H

#include <vector>
#include <memory>
#include <string>
#include <vector>
#include <openssl/x509.h>

namespace cyber {

class X509Certificate {
public:

    typedef std::unique_ptr<X509Certificate> ptr;

    // Public Key Type
    enum PublicKeyType {
        kPublicKeyTypeUnknown,
        kPublicKeyTypeRSA,
        kPublicKeyTypeECC,
        kPublicKeyTypeSM2,
        kPublicKeyTypeEd25519,
    };

    // Key Usage
    // RFC 5280 4.2.1.3
    enum KeyUsage {
        kKeyUsageUnknown  = 0,
        kDigitalSignature = 1 << 0,
        kNonRepudiation   = 1 << 1,
        kKeyEncipherment  = 1 << 2,
        kDataEncipherment = 1 << 3,
        kKeyAgreement     = 1 << 4,
        kKeyCertSign      = 1 << 5,
        kCRLSign          = 1 << 6,
        kEncipherOnly     = 1 << 7,
        kDecipherOnly     = 1 << 8
    };

    // ExtendedKeyUsage
    // RFC 5280 4.2.1.12
    enum ExtendedKeyUsage {
        kServerAuth         = 1 << 0,
        kClientAuth         = 1 << 1,
        kSMIME              = 1 << 2,
        kCodeSigning        = 1 << 3,
        kSGC                = 1 << 3,
        kEmailProtection    = 1 << 4,
        kTimeStamping       = 1 << 5,
        kOcspSigning        = 1 << 6,
    };

    // Certificate Format
    enum CertificateFormat {
        // The data is base64 encoded.
        FORMAT_BASE64_CERT  = 1 << 0,
        // The data contains a DER encoded certificate.
        FORMAT_DER_CERT     = 1 << 1,
        // The data contains a PEM encoded certificate.
        FORMAT_PEM_CERT     = 1 << 2,
    };

    // Create an X509Certificate from the BASE64-encode.
    // Returns NULL on failure.
    static X509Certificate::ptr CreateFromBase64String(
            const std::string &base64_string);

    // Create an X509Certificate from the DER-encode.
    // Returns NULL on failure.
    static X509Certificate::ptr CreateFromDerString(
            const unsigned char *ucDerStr,
            unsigned int uiDerLen);

    // Create an X509Certificate from the PEM-encode.
    // Returns NULL on failure.
    static X509Certificate::ptr CreateFromPemString(
            const std::string &pem_string);

    // Create an X509Certificate from the AUTO-encode.
    // Returns NULL on failure.
    static X509Certificate::ptr CreateFromBytes(
            const std::string &bytes);

    // Construction method.
    explicit X509Certificate() = default;
    ~X509Certificate();

    // Properties.
    X509* value() const { return x509_; }

    // Parses and obtains the certificate content
    // Reference PKI/CA section 9.1.2
    // The latest version is v3, and the default value is v1.
    bool GetVersion(std::string *version);

    // The certificate is uniquely identified and uniformly
    // distributed by the issuer.
    bool GetSerialNumber(std::string *serialNumber);

    // The signature algorithm of the certificate must be
    // the same as that in the certificate domain.
    bool GetSignatureAlgorithm(int *alg);

    // It is used to identify the certificate issuer and
    // contains the identity information of the certificate issuer.
    bool GetIssuerName(std::string *issuer);

    // It is used to identify the certificate holder and
    // contains the identity information of the certificate holder.
    bool GetSubjectName(std::string *subject);
    bool GetSubjectSerialNumber(std::string *subject);

    // Certificate effective date.
    bool GetEffectiveTime(std::string *effective_time);

    // Certificate expiration date.
    bool GetExpirationTime(std::string *expiration_time);

    // Information about the certificate holder`s public key.
    bool GetSubjectPublicKeyInfo(size_t *size_bits, std::string *key_type);

    // Certificate holder`s public key.
    bool GetSubjectPublicKey(std::vector<unsigned char> *public_key);

    // Reference PKI/CA section 9.2.1
    // Standard Extensions
    // Certificate issuer key identification | the critical = false.
    bool GetAuthorityKeyIdentify(std::string *identify);

    // Certificate subject key identification | the critical = true.
    bool GetSubjectKeyIdentify(std::string *identify);

    // Certificate key usage, this field should be verified
    // when using the certificate | the critical = true.
    bool GetKeyUsage(KeyUsage *keyUsage);
    bool GetKeyUsage(std::string *keyUsage);

    // Certificate Extended Key Usage, this field should be verified
    // when using the certificate
    bool GetExtendedKeyUsage(ExtendedKeyUsage *extendedKeyUsage);

    // The basic Constraints extension is used to distinguish whether
    // the certificate holder is a CA or not, and if so, to limit the
    // maximum length of the path that its acknowledgement will give you.
    bool GetBasicConstraints(bool *constraints);

    // The Crl DistributionPoints.
    bool GetCrlDistributionPoints(std::string *crl_points);

    // Check whether the certificate has expired.
    bool HasExpired() const;

    // Check whether the certificate is will expire
    bool WillExpired(int days = 30) const;

    // Returns the PEM encoded data from x509.
    bool GetPEMEncode(std::string & pem_encoded) const;

    // Output the certificate structure to the terminal.
    void Print();

    // Returns the PEM encoded data from a DER encoded certificate.
    // If the return value is true, then the PEM encode certificate is written to
    // |pem_encode|
    // If the return value is false, the error message is written to the log.
    static bool GetPEMEncodeFromDER(const std::string &der_encode,
                                    std::string &pem_encode);

private:
    // Method for creating X509Certificate internal
    static X509Certificate::ptr CreateFromX509(X509 *x509);

    // Method for creating X509Certificate internal
    explicit X509Certificate(X509 *x509);

    // The internal x509 structure.
    X509 *x509_ = nullptr;
};

}

#endif //SVKD_BUILD_X509_CERTIFICATE_H
