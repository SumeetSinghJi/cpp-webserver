## Description

Lightweight C++ console web server capable of hosting and serving web pages from any specified folder.

## License

This project is licensed under the MIT License.

Note: This project includes components from OpenSSL, which is licensed under the Apache License. See the `./src/openssl`license.txt` file for details on the Apache License.

## Requirements

n/a

## Installation

Clone or download a copy of the lightweight web server codebase from: https://github.com/SumeetSinghJi/cpp-webserver (Optional) Build with CMAKE
Download a copy of the lightweight web server codebase from here: https://github.com/SumeetSinghJi/cpp-webserver

## Files

`./headers` - headers
`./headers/lightweight_cpp_webserver.hpp` - Declaration file
`./keys` - contains SSL keys and Certs
`./src` - Third party libraries
`./vscode` - VScode development config files
`./wasm-example` - Default example C++ WebAssembly website
`./website-example` - Default example website
`lightweight_cpp_webserver.cpp` - Definition file
`Change_log.txt` - Documentation for all future code modifications e.g, features/updates/security changes
`CMAKElists.txt` - development config file for building with CMAKE
`main.cpp` - Implementation file
`main.exe` - Executable
`README.md` - Instruction guide
`testing` - Google Test environment

## Example

1. Build or run .exe

2. Enter parameters requested or press ENTER to skip and use defaults 
( 
    Web server IP: 127.0.0.1 
    Web server port: 8080 
    Website directory: 
    website-example/ Website 
    index page: index.html 
)
3. Webserver is now available for client to browse to webserver IP/port to view website in specified directory