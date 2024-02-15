# Lightweight C++ Webserver

## Author
Sumeet Singh

## Dated
22/01/2024

## Description
Lightweight C++ web server library for serving requests with webpages.

## License
This project is licensed under the MIT License.

Note: This project includes components from OpenSSL, which is licensed under the Apache License. See the `./src/openssl/license.txt` file for details on the Apache License.


# Requirements - if building project

OpenSSL installed on device
For Windows;
* "Win64 OpenSSL v3.2.0" found here: https://slproweb.com/products/Win32OpenSSL.html


# Installation

1. Clone or download a copy of the lightweight web server codebase from: https://github.com/SumeetSinghJi/cpp-webserver
(Optional) Build with CMAKE


# Files

* ./src - Third party libraries
* ./website-example - Default example website
* ./wasm-example - Default example C++ WebAssembly website
* ./headers - headers
* ./headers/lightweight_cpp_webserver.hpp - Declaration file
* lightweight_cpp_webserver.cpp - Definition file
* main.cpp - Implementation file
* main.exe - Executable
* testing - Google Test environment


# Example

1. Build or run .exe
2. Enter parameters requested or press ENTER to skip and use defaults (
    Web server IP: 127.0.0.1
    Web server port: 8080
    Website directory: website-example/
    Website index page: index.html
)
3. Browse to webserver IP to view website