#pragma once
#include <stdexcept>
#include <iostream>

using namespace std;

class KeyError final : public runtime_error {
public:
    explicit KeyError(const string& message)
        : runtime_error("KeyError " + message) {};
};

class ServerError final : public runtime_error {
public:
    explicit ServerError(const string& message)
        : runtime_error("Server error " + message) {};
};

class CertificateError final : public runtime_error {
public:
    explicit CertificateError(const string& message)
        : runtime_error("Certificate error " + message) {};
};

class CRLError final : public runtime_error {
public:
    explicit CRLError(const string& message)
        : runtime_error("CRL error " + message) {};
};