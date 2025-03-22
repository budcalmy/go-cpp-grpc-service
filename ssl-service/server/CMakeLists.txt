cmake_minimum_required(VERSION 3.20)
project(grpcpp_server)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
find_package(Protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

set(PROTO_FILES proto/init.proto)
add_library(protolib ${PROTO_FILES})
target_link_libraries(protolib gRPC::grpc++)

target_include_directories(protolib PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
get_target_property(grpc_cpp_plugin_location gRPC::grpc_cpp_plugin LOCATION)
protobuf_generate(TARGET protolib LANGUAGE cpp)
protobuf_generate(TARGET protolib LANGUAGE grpc
    GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc
    PLUGIN "protoc-gen-grpc=${grpc_cpp_plugin_location}")

set(INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/grpc-impl
                ${CMAKE_SOURCE_DIR}/ssl-utils
                ${CMAKE_SOURCE_DIR}/errors
                ${CMAKE_SOURCE_DIR}/grpc-server
                ${CMAKE_SOURCE_DIR}/ssl-structs)
include_directories(${INCLUDE_DIRS})

add_executable(server main.cc)
target_link_libraries(server protolib)
target_link_libraries(server OpenSSL::SSL OpenSSL::Crypto SQLite::SQLite3)
target_compile_definitions(server PRIVATE SQLITE_HAS_CODEC)
