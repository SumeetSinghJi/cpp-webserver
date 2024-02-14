/*
    Author: Sumeet Singh
    Dated: 22/01/2024
    Minimum C++ Standard: C++11
    Purpose: Declaration file
    License: MIT License
    Description: read the attached README.md file
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

#ifdef _WIN32 // Windows hardware network interface required headers
#include <winsock2.h>
#include <WS2tcpip.h> // for inet_ntop() to extract client IP
#else   // Linux hardware network interface required headers
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
    std::string webserverIPAddress;
    int webserverPortNumber;
    std::string clientIPAddress; // Extracted in run_web_server()
    int bytesReceived;
    std::string logPath;
    std::string requestLine;

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
