/*
    Author: Sumeet Singh
    Dated: 22/01/2024
*/

#include "headers/lightweight_cpp_webserver.hpp"
#include "headers/custom_openssl_context.hpp"

int main()
{
    lightweight_cpp_webserver server("127.0.0.1", 8080);
    custom_openssl_context my_custom_openssl_context;
    if (!my_custom_openssl_context.initialise_ssl_context("server.crt", "server.key")) {
        std::cerr << "Failed to initialize SSL context." << std::endl;
    }
    if (server.initialise_web_server())
    {
        server.run_web_server();
    }
    return 0;
}