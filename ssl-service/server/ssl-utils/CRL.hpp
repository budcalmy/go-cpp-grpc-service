#pragma once
#include <iostream>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "../ssl-structs/CRLStructs.hpp"
#include "../time-utils/Time.hpp"
#include "../errors/Errors.hpp"
#include "../ssl-utils/Key.hpp"
#include "../ssl-utils/Certificate.hpp"

using namespace std;

class CRLService final
{
public:
    static unique_ptr<CRLResponceStruct> generateCRL(
        const string &pkeyPem,
        const string &certPem,
        uint validityDays)
    {
        unique_ptr<CRLResponceStruct> crlResp = make_unique<CRLResponceStruct>();

        unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> privateKey(
            KeyService::loadKeyFromPem(pkeyPem), EVP_PKEY_free);
        if (!privateKey)
            throw CRLError("Ошибка загрузки приватного ключа");

        unique_ptr<X509, decltype(&X509_free)> issuerCert(
            CertificateService::loadCertFromPem(certPem), X509_free);
        if (!issuerCert)
            throw CRLError("Ошибка загрузки сертификата");

        unique_ptr<X509_CRL, decltype(&X509_CRL_free)> crl(X509_CRL_new(), X509_CRL_free);
        if (!crl)
            throw CRLError("Ошибка создания CRL");

        X509_CRL_set_version(crl.get(), 2);

        X509_NAME *issuerName = X509_get_subject_name(issuerCert.get());
        X509_CRL_set_issuer_name(crl.get(), issuerName);

        ASN1_TIME *now = ASN1_TIME_new();
        ASN1_TIME_set(now, time(nullptr));
        X509_CRL_set_lastUpdate(crl.get(), now);

        ASN1_TIME *nextUpdate = ASN1_TIME_new();
        ASN1_TIME_adj(nextUpdate, time(nullptr), validityDays * 24 * 60 * 60, 0);
        X509_CRL_set_nextUpdate(crl.get(), nextUpdate);

        ASN1_TIME_free(now);
        ASN1_TIME_free(nextUpdate);

        if (!X509_CRL_sign(crl.get(), privateKey.get(), EVP_sha256()))
            throw CRLError("Ошибка подписания CRL");

        unique_ptr<BIO, decltype(&BIO_free)> crlBio(BIO_new(BIO_s_mem()), BIO_free);
        if (!PEM_write_bio_X509_CRL(crlBio.get(), crl.get()))
            throw CRLError("Ошибка преобразования CRL в PEM");

        char *pemData = nullptr;
        long pemLen = BIO_get_mem_data(crlBio.get(), &pemData);
        crlResp->crlPem.assign(pemData, pemLen);
        crlResp->issuedAt = getCurrentTimestamp();
        crlResp->expiresAt = getCurrentTimestamp(validityDays);

        return crlResp;
    }

    static X509_CRL *loadCRLFromPem(const string &crlPem)
    {
        BIO *bio = BIO_new_mem_buf(crlPem.c_str(), -1);
        if (!bio)
        {
            throw CRLError("Ошибка создания BIO.");
        }

        X509_CRL *crl = PEM_read_bio_X509_CRL(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!crl)
        {
            char buf[120];
            ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
            throw CRLError(std::string("Ошибка загрузки CRL: ") + buf);
        }

        return crl;
    }

private:
    static string crlToPem(X509_CRL *crl)
    {
        unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
        if (!bio || PEM_write_bio_X509_CRL(bio.get(), crl) == 0)
        {
            X509_CRL_free(crl);
            throw CRLError("Ошибка при преобразовании CRL в PEM");
        }
        size_t length = BIO_ctrl_pending(bio.get());
        string pem(length, '\0');
        BIO_read(bio.get(), pem.data(), length);

        return pem;
    }
};