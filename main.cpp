/*
    Author: Sumeet Singh
    Dated: 22/01/2024
*/

#include "headers/lightweight_cpp_webserver.hpp"

int main()
{
    lightweight_cpp_webserver server("127.0.0.1", 8080);
    if (server.initialise_web_server())
    {
        server.run_web_server();
    }
    return 0;
}