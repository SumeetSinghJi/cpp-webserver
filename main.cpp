/*
    Author: Sumeet Singh
    Dated: 22/01/2024
    Minimum C++ Standard: C++11
    Purpose: Implementation file
    License: MIT License
    Description: read the attached README.md file
*/

#include "headers/lightweight_cpp_webserver.hpp" // Declarations file
#include "headers/custom_openssl_context.hpp" // Declaration/Definition file (combined to segregate third party library code)

int main()
{
    lightweight_cpp_webserver server("127.0.0.1", 8080);
    custom_openssl openssl_context;
    if (!openssl_context.initialise_ssl_context("server.crt", "server.key")) {
        std::cerr << "Failed to initialize SSL context." << std::endl;
    }
    if (server.initialise_web_server())
    {
        server.run_web_server();
    }
    return 0;
}