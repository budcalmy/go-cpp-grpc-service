#pragma once
#include <iostream>
#include <memory>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/asn1.h>
#include <openssl/err.h>

#include "../errors/Errors.hpp"
#include "../time-utils/Time.hpp"
#include "../ssl-structs/KeyStructs.hpp"

using namespace std;

class KeyService final
{
public:
    static unique_ptr<PrivateKeyResponse> generateKey(
        const string &keyType,
        uint keyLength,
        uint validityDays,
        const string &curve = "")
    {
        unique_ptr<PrivateKeyResponse> pkey = make_unique<PrivateKeyResponse>();

        pkey.get()->createdAt = getCurrentTimestamp();
        pkey.get()->keyType = keyType;
        pkey.get()->keyLength = to_string(keyLength);

        EVP_PKEY *evp_pkey = nullptr;

        if (keyType == "RSA")
        {
            EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
            if (!ctx)
                throw KeyError("Ошибка создания контекста для ключа RSA");

            if (EVP_PKEY_keygen_init(ctx) <= 0)
            {
                EVP_PKEY_CTX_free(ctx);
                throw KeyError("Ошибка инициализации генерации ключа");
            }

            if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keyLength) <= 0)
            {
                EVP_PKEY_CTX_free(ctx);
                throw KeyError("Ошибка установки длины ключа");
            }

            if (EVP_PKEY_keygen(ctx, &evp_pkey) <= 0)
            {
                EVP_PKEY_CTX_free(ctx);
                throw KeyError("Ошибка генерации RSA-ключа");
            }

            EVP_PKEY_CTX_free(ctx);
        }
        else
        {
            throw KeyError("Неподдерживаемый тип ключа.");
        }

        pkey->keyPem = keyToPem(evp_pkey);
        pkey->expiresAt = getCurrentTimestamp(validityDays);

        EVP_PKEY_free(evp_pkey);

        return pkey;
    }

    static EVP_PKEY *loadKeyFromPem(const string &keyPem)
    {
        BIO *bio = BIO_new_mem_buf(keyPem.c_str(), -1); // Создаём BIO из строки PEM
        if (!bio)
        {
            throw KeyError("Ошибка создания BIO.");
        }

        EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio); 

        if (!pkey)
        {
            char buf[120];
            ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
            throw KeyError(std::string("Ошибка загрузки ключа: ") + buf);
        }

        return pkey;
    }

private:
    static string keyToPem(EVP_PKEY *pkey)
    {
        unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
        if (!bio || PEM_write_bio_PrivateKey(bio.get(), pkey, nullptr, nullptr, 0, nullptr, nullptr) == 0)
        {
            EVP_PKEY_free(pkey);
            throw KeyError("Ошибка при преобразовании ключа в PEM");
        }
        size_t length = BIO_ctrl_pending(bio.get());
        string pem(length, '\0');
        BIO_read(bio.get(), pem.data(), length);

        return pem;
    }
};