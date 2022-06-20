cmake_minimum_required(VERSION 3.10)
project(antywirus-bso)

add_executable(antivirus Source/main.cpp)

find_package(OpenSSL REQUIRED)
target_link_libraries(antivirus OpenSSL::SSL)

target_compile_options(antivirus PRIVATE -Wall -Wextra -Werror -std=c++17 -Lopenssl/openssl-0.9.8k/ -lssl -lcrypto -Iopenssl/openssl-0.9.8k/include -lstdc++fs)
