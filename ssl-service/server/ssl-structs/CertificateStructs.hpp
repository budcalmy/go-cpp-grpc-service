#pragma once
#include <iostream>
#include <vector>

using namespace std;

struct CertSubject {
    string CN;
    string O;
    string C;
    string L;
};

struct CertificateResponse {
    string certId;
    CertSubject subject;
    string status;
    string issuedAt;
    string expiresAt;
    string certPem;
    string pkeyId;

    // optional<string> err;
};