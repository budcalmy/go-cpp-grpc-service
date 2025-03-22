#pragma once
#include <grpcpp/grpcpp.h>
#include "proto/init.grpc.pb.h"
#include "proto/init.pb.h"

#include "../ssl-utils/Key.hpp"
#include "../ssl-utils/Certificate.hpp"
#include "../ssl-utils/CRL.hpp"

using grpc::Server;
using grpc::Status;
using grpc::StatusCode;

class InitSystemServiceImpl final : public InitSystem::Service
{
    Status GeneratePrivateKey(::grpc::ServerContext *context, const ::PrivateKeyConfig *request, ::PrivateKey *response)
    {
        try
        {
            unique_ptr<PrivateKeyResponse> pkey = KeyService::generateKey(
                request->keytype(),
                request->keylength(),
                request->validitydays());
            if (!pkey)
            {
                response->set_err("Неудалось создать приватный ключ.");
                return Status(StatusCode::INTERNAL, "Неудалось создать приватный ключ.");
            }

            response->set_keylength(pkey->keyLength);
            response->set_keytype(pkey->keyType);
            response->set_createdat(pkey->createdAt);
            response->set_expiresat(pkey->expiresAt);
            response->set_keypem(pkey->keyPem);
            return Status::OK;
        }
        catch (KeyError &key_err)
        {
            response->set_err(key_err.what());
            return Status(StatusCode::INTERNAL, key_err.what());
        }
    }
    Status GenerateSelfSignedCertificate(::grpc::ServerContext *context, const ::SelfSignedCertificateConfig *request, ::SelfSignedCertificate *response)
    {
        try
        {
            CertSubject subj = {request->subject().cn(),
                                request->subject().o(),
                                request->subject().c(),
                                request->subject().l()};
            unique_ptr<CertificateResponse> cert = CertificateService::generateCertificate(
                request->pkeypem(),
                subj,
                request->validitydays());

            if (!cert)
            {
                response->set_err("Не удалось создать сертификат.");
                return Status(StatusCode::INTERNAL, "Не удалось создать сертификат.");
            }

            response->mutable_subject()->set_cn(cert->subject.CN);
            response->mutable_subject()->set_o(cert->subject.O);
            response->mutable_subject()->set_c(cert->subject.C);
            response->mutable_subject()->set_l(cert->subject.L);
            response->set_issuedat(cert->issuedAt);
            response->set_expiresat(cert->expiresAt);
            response->set_certpem(cert->certPem);
            response->set_status(cert->status);
            return Status::OK;
        }
        catch (CertificateError &cert_err)
        {
            response->set_err(cert_err.what());
            return Status(StatusCode::INTERNAL, cert_err.what());
        }
    }
    
    Status InitSys(::grpc::ServerContext *context, const ::InitConfig *request, ::grpc::ServerWriter<::InitEvent> *writer)
    {
        InitEvent event;
        try
        {
            event.set_step("GENERATING PRIVATE KEY");
            event.set_status("IN PROGRESS");
            writer->Write(event);

            unique_ptr<PrivateKeyResponse> pkey = KeyService::generateKey(
                request->keyconfig().keytype(),
                request->keyconfig().keylength(),
                request->keyconfig().validitydays());

            if (!pkey)
            {
                event.set_status("Failed");
                event.set_details("Ошибка генерации ключа");
                writer->Write(event);
                return Status(StatusCode::INTERNAL, "Ошибка генерации ключа");
            }

            PrivateKey pkeyResponse;
            pkeyResponse.set_keytype(pkey->keyType);
            pkeyResponse.set_keylength(pkey->keyLength);
            pkeyResponse.set_createdat(pkey->createdAt);
            pkeyResponse.set_expiresat(pkey->expiresAt);
            pkeyResponse.set_keypem(pkey->keyPem);
            event.set_status("SUCCESS");
            event.mutable_pkey()->CopyFrom(pkeyResponse);
            writer->Write(event);

            event.set_step("GENERATING SELF SIGNED CERTIFICATE");
            event.set_status("IN PROGRESS");
            writer->Write(event);

            CertSubject subj = {request->certsubject().cn(),
                                request->certsubject().o(),
                                request->certsubject().c(),
                                request->certsubject().l()};

            unique_ptr<CertificateResponse> cert = CertificateService::generateCertificate(
                pkey->keyPem,
                subj,
                request->certvaliditydays());

            if (!cert)
            {
                event.set_status("Failed");
                event.set_details("Ошибка генерации сертификата");
                writer->Write(event);
                return Status(StatusCode::INTERNAL, "Ошибка генерации сертификата");
            }

            SelfSignedCertificate certResponse;
            certResponse.mutable_subject()->set_cn(cert->subject.CN);
            certResponse.mutable_subject()->set_o(cert->subject.O);
            certResponse.mutable_subject()->set_c(cert->subject.C);
            certResponse.mutable_subject()->set_l(cert->subject.L);
            certResponse.set_issuedat(cert->issuedAt);
            certResponse.set_expiresat(cert->expiresAt);
            certResponse.set_certpem(cert->certPem);
            certResponse.set_status(cert->status);

            event.set_status("SUCCESS");
            event.mutable_cert()->CopyFrom(certResponse);
            writer->Write(event);

            event.set_step("GENERATING CRL");
            event.set_status("IN PROGRESS");
            writer->Write(event);

            unique_ptr<CRLResponceStruct> crlresp = CRLService::generateCRL(
                pkey->keyPem,
                cert->certPem,
                request->crlvaliditydays());

            if (!crlresp)
            {
                event.set_status("Failed");
                event.set_details("Ошибка генерации CRL");
                writer->Write(event);
                return Status(StatusCode::INTERNAL, "Ошибка генерации CRL");
            }

            CRL crl;
            crl.set_crlpem(crlresp->crlPem);
            crl.set_issuedat(crlresp->issuedAt);
            crl.set_expiresat(crlresp->expiresAt);

            event.set_status("SUCCESS");
            event.mutable_crl()->CopyFrom(crl);
            writer->Write(event);

            event.set_step("Initialization Complete");
            event.set_status("SUCCESS");
            writer->Write(event);

            return Status::OK;
        }
        catch (std::exception &any_ex) {
            event.set_status("FAILDED");
            event.set_details(any_ex.what());
            writer->Write(event);
            return Status(StatusCode::INTERNAL, any_ex.what());
        }
    }
};