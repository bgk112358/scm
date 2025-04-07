// 
// Create by kong
// Copyright 2025 China Automotive Research Software Evaluation Co., Ltd.
//
#ifndef SVKD_BUILD_UNIQUEPTR_UTIL_H
#define SVKD_BUILD_UNIQUEPTR_UTIL_H

#include <memory>

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/cms.h>
#include <openssl/pkcs12.h>

namespace internal {

// The Enable parameter is ignored and only exists so specializations can use
// Declaration template.
    template<typename T, typename Enable = void>
    struct DeleterImpl {
    };

    struct Deleter {
        template<typename T>
        void operator()(T *ptr) {
            DeleterImpl<T>::Free(ptr);
        }
    };

    template<typename T>
    using UniquePtr = std::unique_ptr<T, Deleter>;

}

#define OPENSSL_MAKE_DELETER(type, deleter)       \
  namespace internal {                            \
  template <>                                     \
  struct DeleterImpl<type> {                      \
    static void Free(type *ptr) { deleter(ptr); } \
  };                                              \
}

OPENSSL_MAKE_DELETER(ASN1_OBJECT,    ASN1_OBJECT_free)
OPENSSL_MAKE_DELETER(ASN1_STRING,    ASN1_STRING_free)
OPENSSL_MAKE_DELETER(ASN1_TYPE,      ASN1_TYPE_free)
OPENSSL_MAKE_DELETER(BIGNUM,         BN_free)
OPENSSL_MAKE_DELETER(BIO,            BIO_free_all)
OPENSSL_MAKE_DELETER(EVP_CIPHER_CTX, EVP_CIPHER_CTX_free)
OPENSSL_MAKE_DELETER(EVP_PKEY,       EVP_PKEY_free)
OPENSSL_MAKE_DELETER(EVP_PKEY_CTX,   EVP_PKEY_CTX_free)
OPENSSL_MAKE_DELETER(PKCS7,          PKCS7_free)
OPENSSL_MAKE_DELETER(PKCS12,         PKCS12_free)
OPENSSL_MAKE_DELETER(X509,           X509_free)
OPENSSL_MAKE_DELETER(X509_CRL ,      X509_CRL_free)
OPENSSL_MAKE_DELETER(X509_REQ ,      X509_REQ_free)
OPENSSL_MAKE_DELETER(X509_STORE ,    X509_STORE_free)
OPENSSL_MAKE_DELETER(X509_STORE_CTX, X509_STORE_CTX_free)
OPENSSL_MAKE_DELETER(STACK_OF(X509_CRL) , sk_X509_CRL_free)
OPENSSL_MAKE_DELETER(CMS_ContentInfo , CMS_ContentInfo_free)
OPENSSL_MAKE_DELETER(STACK_OF(X509_ATTRIBUTE) , sk_X509_ATTRIBUTE_free)

#endif //SVKD_BUILD_UNIQUEPTR_UTIL_H
