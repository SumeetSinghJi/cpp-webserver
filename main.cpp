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
    std::signal(SIGINT, lightweight_cpp_webserver::signal_handler);

    lightweight_cpp_webserver server;

    std::cout << "Enter IP address for webserver (press enter for default IP: 127.0.0.1): ";
    server.default_string_initialisation_inputs(server.get_webserver_IP_address());
    std::cout << "IP entered is: " << server.get_webserver_IP_address() << std::endl;

    std::cout << "Enter Port number for webserver (press enter for default Port: 8080): ";
    server.default_int_initialisation_inputs(server.get_webserver_port_address());
    std::cout << "Port number entered is: " << server.get_webserver_port_address() << std::endl;
    

    if (!server.initialise_ssl_context("keys/server.crt", "keys/server.key"))
    {
        return 1;
    }

    if (!server.initialise_web_server() || !server.run_web_server())
    {
        return 1;
    }

    return 0;
}
