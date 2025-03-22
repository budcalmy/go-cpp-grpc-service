#pragma once
#include <iostream>

using namespace std;

struct PrivateKeyResponse
{
    string keyType;
    string keyLength; 
    string createdAt;
    string expiresAt;
    string keyPem;
    
    // optional<string> err;
};