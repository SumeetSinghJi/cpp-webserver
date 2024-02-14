/*
    Author: Sumeet Singh
    Dated: 22/01/2024
    Minimum C++ Standard: C++11
    Purpose: Implementation file for starting the web server with SSL support
    License: MIT License
    Description: This program initializes a lightweight web server with SSL support
                 and runs it on localhost at port 8080.
*/

#include "headers/lightweight_cpp_webserver.hpp" // Declarations file

int main()
{
    std::signal(SIGINT, lightweight_cpp_webserver::signal_handler); // on CTRL+C perform SSL Cleanup

    lightweight_cpp_webserver server("127.0.0.1", 8080);

    if (!server.initialise_ssl_context("keys/server.crt", "keys/server.key"))
    {
        return 1;
    }

    server.initialise_web_server();

    server.run_web_server();

    return 0;
}
