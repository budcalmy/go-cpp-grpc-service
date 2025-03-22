#pragma once
#include <iostream>

using namespace std;

struct CRLResponceStruct
{
    string crlPem;
    string issuedAt;
    string expiresAt;

    // optional<string> err;
};