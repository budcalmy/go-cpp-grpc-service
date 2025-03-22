#include <iostream>
#include <grpcpp/grpcpp.h>
#include "grpc-impl/InitSystem.hpp"
#include "grpc-server/StartStopServer.hpp"

int main()
{

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    StartStopServerService serverManager;

    InitSystemServiceImpl initService;

    const std::string address = "0.0.0.0:50051";

    try
    {
        serverManager.startServer(address, {&initService});
        std::cin.get();
    }
    catch (const ServerError &ser_err)
    {
        std::cerr << ser_err.what() << std::endl;
    }

    return 0;
}