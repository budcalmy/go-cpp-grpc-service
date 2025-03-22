#pragma once
#include <iostream>
#include <memory>
#include <vector>

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/asn1.h>
#include <openssl/err.h>

#include "../time-utils/Time.hpp"
#include "../ssl-structs/CertificateStructs.hpp"
#include "../ssl-structs/KeyStructs.hpp"
#include "../ssl-utils/Key.hpp"

using namespace std;

class CertificateService final
{
public:
    static unique_ptr<CertificateResponse> generateCertificate(
        const string &pkeyPem,
        CertSubject &subj,
        uint validityDays)
    {
        unique_ptr<CertificateResponse> certResp = make_unique<CertificateResponse>();

        certResp->issuedAt = getCurrentTimestamp();
        certResp->subject = subj;

        X509 *cert = X509_new();

        if (!cert)
            throw CertificateError("Не удалось создать X509 сертификат");

        X509_set_version(cert, 2);

        // Генерация серийного номера
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

        // Установка срока действия
        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert), validityDays * 24 * 60 * 60);

        unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> evp_pkey(
            KeyService::loadKeyFromPem(pkeyPem), EVP_PKEY_free);
        if (!evp_pkey)
        {
            X509_free(cert);
            throw CertificateError("Ошибка загрузки ключа");
        }
        
        X509_set_pubkey(cert, evp_pkey.get());


        // Установка субъекта и эмитента
        X509_NAME *name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char *>(subj.C.c_str()), -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char *>(subj.O.c_str()), -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char *>(subj.L.c_str()), -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char *>(subj.CN.c_str()), -1, -1, 0);
        X509_set_issuer_name(cert, name);

        if (!X509_sign(cert, evp_pkey.get(), EVP_sha256()))
        {
            X509_free(cert);
            throw CertificateError("Ошибка при подписании сертификата");
        }

        certResp->certPem = certToPem(cert);
        certResp->expiresAt = getCurrentTimestamp(validityDays);
        certResp->status = "Activate"; // TODO enum types

        return certResp;
    }

    static X509 *loadCertFromPem(const string &certPem)
    {
        BIO *bio = BIO_new_mem_buf(certPem.data(), certPem.size());
        if (!bio)
        {
            throw CertificateError("Ошибка создания BIO");
        }

        X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        if (!cert)
        {
            BIO_free(bio);
            throw CertificateError("Ошибка загрузки сертификата из PEM");
        }

        BIO_free(bio);

        return cert;
    }

private:

    static string certToPem(X509 *cert)
    {
        if (!cert)
        {
            throw CertificateError("Сертификат не может быть nullptr");
        }

        BIO *bio = BIO_new(BIO_s_mem());
        if (!bio)
        {
            throw CertificateError("Ошибка создания BIO");
        }

        if (!PEM_write_bio_X509(bio, cert))
        {
            BIO_free(bio);
            throw CertificateError("Ошибка преобразования сертификата в PEM");
        }

        char *pemData;
        long pemLength = BIO_get_mem_data(bio, &pemData);

        std::string pemCert(pemData, pemLength);

        BIO_free(bio);

        return pemCert;
    }
};
