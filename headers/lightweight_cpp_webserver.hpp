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
#include <iomanip>        // for put_time()
#include <csignal>        // If CTRL+C signal given, perform SSL shutdown
#include <thread>         // Signal/Handle sleep after cleanup for verbose output
#include <chrono>         // Signal/Handle sleep after cleanup for verbose output

#ifdef _WIN32 // Windows hardware network interface required headers
#include <winsock2.h>
#include <WS2tcpip.h> // for inet_ntop() to extract client IP
#include <Windows.h> // for testing on windows window terminal executable close button, perform exit cleanup
#else   // Linux hardware network interface required headers
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

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

    struct sockaddr_in server;
    int server_len = 0;
    int BUFFER_SIZE = 30720;
    std::string webserverIPAddress = "127.0.0.1";
    int webserverPortNumber = 8080;
    std::string clientIPAddress = "";
    std::string WebsiteFolderName = "website-example/";
    std::string websiteIndexFile = "index.html";
    int bytesReceived = 0;
    std::string logPath = "";
    std::string requestLine = "";

    // SSL related members
    SSL_CTX *ssl_ctx;
    SSL *ssl;

    // Signal shutdown
    static lightweight_cpp_webserver* serverInstance;

public:
    lightweight_cpp_webserver();

    void set_IP_address(const std::string &ipAddress);
    void set_port_number(int portNumber);
    void set_website_directory(std::string WebsiteFolder);
    void set_website_index(std::string indexFileName);

    std::string get_webserver_IP_address();
    int get_webserver_port_address();
    std::string get_website_directory();
    std::string get_website_index();

    bool is_valid_IP_address(const std::string &ipAddress);
    bool is_valid_port_address(int &portNumber);

    bool initialise_web_server();

    bool run_web_server();

    bool read_and_validate_headers(std::vector<std::string> &headers);

    bool accept_client_request();

    void output_logs(const std::string &header);

    // void send_response(int socket, const std::string &response);

    std::string get_requested_page(const std::string &url);

    std::string read_static_html_file(std::string filePath);

    void handle_static_file_request(const std::string &requestedPage);

    void serve_error_page(const std::string &statusCode, const std::string &errorPage);

    bool ssl_initialise_context(const std::string &certFile, const std::string &keyFile);
    static void ssl_info_callback(const SSL *ssl, int type, int val);
    bool ssl_handshake();
    bool ssl_read_request();
    bool ssl_write_response(const std::string &response);
    bool ssl_shutdown();

    static void signal_handler(int signum);

    void default_string_initialisation_inputs(const std::string& defaultValue);
};
