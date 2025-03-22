#pragma once
#include <iostream>
#include <thread>
#include <vector>
#include <grpcpp/grpcpp.h>

#include "../grpc-impl/InitSystem.hpp"

class StartStopServerService final {
public:
    StartStopServerService() = default;
    ~StartStopServerService() {
        stopServer();
    }

    void startServer(const std::string& address, const std::vector<grpc::Service*>& services) {
        std::cout << "Запуск сервера..\n";
        if (serverThread.joinable()) {
            throw ServerError("Сервер уже запущен.");
            return;
        }

        grpc::ServerBuilder builder;
        builder.AddListeningPort(address, grpc::InsecureServerCredentials());

        for (auto* service : services) {
            builder.RegisterService(service);
        }

        server = builder.BuildAndStart();
        if (!server) {
            throw ServerError("Неудалось запустить grpc сервер.");
        }

        std::cout << "Сервер запущен на " << address << std::endl;

        serverThread = std::thread([this]() {
            server->Wait();
        });

        serverThread.detach();
    }

    void stopServer() {
        std::cout << "Остановка сервера..\n";
        if (server) {
            server->Shutdown();
            server.reset();
        }
    }

private:
    std::unique_ptr<grpc::Server> server;
    std::thread serverThread;
};