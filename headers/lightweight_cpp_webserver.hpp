/*
    Author: Sumeet Singh
    Dated: 22/01/2024
    File: Declaration file
    Description: read the attached README.md file
    Minimum C++ Standard: C++11
*/

#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <openssl/ssl.h>  // for SSL
#include <openssl/err.h>  // for SSL
#include <fstream>        // for output file/serving .html files to client browser
#include <filesystem>     // for getenv for output file to the correct environment
#include <chrono>         // for timestamping logs

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

// Contents of the header file go here
class lightweight_cpp_webserver
{
private:
#ifdef _WIN32
    SOCKET serverSocket;
    SOCKET newServerSocket;
    WSADATA wsaData;
#else
    int serverSocket;
    int newServerSocket;
#endif

    // Global private variables
    struct sockaddr_in server;
    int server_len;
    int BUFFER_SIZE;
    std::string clientIPAddress;
    int clientPortNumber;
    int bytesReceived;
    std::string logPath;
    std::string requestLine;

    // std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> sslContext;

public:
    lightweight_cpp_webserver(const std::string &ipAddress, int portNumber);

    void setIPAddress(const std::string &ipAddress);

    void setPortNumber(int portNumber);

    bool initialise_web_server();

    bool run_web_server();

    bool read_and_validate_headers(std::vector<std::string> &headers);

    bool accept_client_request();

    bool isValidIPAddress(const std::string &ipAddress);

    bool isValidPortAddress(int &portNumber);

    void output_logs(const std::string &header);

    void send_response(int socket, const std::string &response);

    std::string get_requested_page(const std::string &url);

    std::string read_static_html_file(std::string filePath);

    void handle_static_file_request(const std::string &requestedPage);

    void serve_error_page(const std::string &statusCode, const std::string &errorPage);
};
