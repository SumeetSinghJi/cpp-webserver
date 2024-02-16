/*
    Author: Sumeet Singh
    Dated: 22/01/2024
    Minimum C++ Standard: C++11
    Purpose: Definition file
*/

#include "headers/lightweight_cpp_webserver.hpp" // Declarations file

/* TO DO
* favicon is being looked for why?
 * Download into ./src OpenSSL, and include and link to project, may be necesary to specify bin path for CMAKE
 * SSL not integrated
 * Setup testing
 * Content Security Policy (CSP)
 * use #include <boost/asio.hpp> for Asynchronous
 * WASM setup test
 */

lightweight_cpp_webserver *lightweight_cpp_webserver::serverInstance = nullptr;

lightweight_cpp_webserver::lightweight_cpp_webserver() { serverInstance = this; }

void lightweight_cpp_webserver::set_IP_address(const std::string &ipAddress)
{
    // Set the webserver IP address when initialised e.g; lightweight_cpp_webserver server("127.0.0.1", 8080);
    if (is_valid_IP_address(ipAddress))
    {
        this->webserverIPAddress = ipAddress;
    }
    else
    {
        std::cout << "Error: Invalid IP address range. Must be 4 octets in ranges 0 - 255 e.g, 10.10.10.10" << std::endl;
        // Must be private address in class A (10.), B (172.16.31.) or C (192.168.)"
    }
}
void lightweight_cpp_webserver::set_port_number(int portNumber)
{
    if (is_valid_port_address(portNumber))
    {
        this->webserverPortNumber = portNumber;
    }
    else
    {
        std::cout << "Error: Invalid port range. Must be > 1024 or < 65535." << std::endl;
    }
}
void lightweight_cpp_webserver::set_website_directory(std::string WebsiteFolder)
{
    this->WebsiteFolderName = WebsiteFolder;
}
void lightweight_cpp_webserver::set_website_index(std::string indexFileName)
{
    this->websiteIndexFile = indexFileName;
}

std::string lightweight_cpp_webserver::get_webserver_IP_address()
{
    return webserverIPAddress;
};
int lightweight_cpp_webserver::get_webserver_port_address()
{
    return webserverPortNumber;
}
std::string lightweight_cpp_webserver::get_website_directory()
{
    return WebsiteFolderName;
};
std::string lightweight_cpp_webserver::get_website_index()
{
    return websiteIndexFile;
};

bool lightweight_cpp_webserver::is_valid_IP_address(const std::string &ipAddress)
{
    // Split the IP address into octets
    std::vector<int> octets;
    std::istringstream ss(ipAddress);
    std::string octet;
    while (std::getline(ss, octet, '.'))
    {
        octets.push_back(std::stoi(octet));
    }

    // Check if the IP address has four octets
    if (octets.size() != 4)
    {
        return false;
    }

    // Check if each octet falls within the range [0, 255]
    for (int octetValue : octets)
    {
        if (octetValue < 0 || octetValue > 255)
        {
            return false;
        }
        return true;
    }

    /*
    // Check if the IP address falls within the specified ranges
    if ((octets[0] == 10) ||
        (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) ||
        (octets[0] == 192 && octets[1] == 168))
    {
        return true;
    }
    */

    return false;
}
bool lightweight_cpp_webserver::is_valid_port_address(int &portNumber)
{
    // Security - Input validation
    if (portNumber >= 1024 && portNumber <= 65535)
    {
        return true;
    }
    return false;
};

bool lightweight_cpp_webserver::initialise_web_server()
{
    std::cout << "Attempting to create a web server" << std::endl;

// Windows - Initialise Web server
#ifdef _WIN32
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        std::cout << "Could not initialise Winsocket" << std::endl;
    }
#endif

    // Create a web socket
    // AF_INET - IPV4 (Domain)
    // SOCK_STREAM - Asynchronous, Full-duplex (Type)
    // IPPROTO_TCP - TCP (Protocol)
    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET)
    {
        std::cout << "Error: Could not create a web socket" << std::endl;
    }

    // bind socket to address
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(webserverIPAddress.c_str());
    server.sin_port = htons(webserverPortNumber);
    server_len = sizeof(server);

    /*
        Server socket IP and Port assignmeent start with order of functions bind(), getsockname() listen()
        all 3 are necessary
        bind() checks if the initialised IP and Port number listed can be assigned by the Operating System
        e.g; lightweight_cpp_webserver server("127.0.0.1", 8080);
    */
    if (bind(serverSocket, (SOCKADDR *)&server, server_len) != 0)
    {
        std::cout << "Error: Could not bind IP address: " << webserverIPAddress << ":" << webserverPortNumber << " to web server, web socket" << std::endl;
    }

    // Get the actual port number chosen by the OS after bind()
    if (getsockname(serverSocket, (SOCKADDR *)&server, &server_len) == -1)
    {
        std::cout << "Error: Could not get actual port number" << std::endl;
        closesocket(serverSocket);
        return false;
    }

    // listen is another check after getsockname()
    if (listen(serverSocket, 20) != 0) // (serverSocket, 20) = 20 concurrent client connections
    {
        std::cout << "Error: Could not listen to anything on server address: " << webserverIPAddress << ":" << webserverPortNumber << std::endl;
    }
    std::cout << "Web server created successfully." << std::endl;
    return true;
}

bool lightweight_cpp_webserver::run_web_server()
{
    while (true)
    {
        // Accept client request
        if (!accept_client_request())
        {
            break;
        }

        // Read and validate headers
        std::vector<std::string> headers;
        if (!read_and_validate_headers(headers))
        {
            closesocket(newServerSocket);
            continue;
        }

        // Extract the requested path from the request line
        std::istringstream requestLineStream(requestLine);
        std::string method, path, protocol;
        requestLineStream >> method >> path >> protocol;

        // Determine the corresponding page based on the URL
        std::cout << "Finding path of page requested: " + path << std::endl;
        std::string requestedPage = get_requested_page(path);

        // Handle static file requests
        if (method == "GET" && requestedPage != "")
        {
            handle_static_file_request(requestedPage);
        }
        else
        {
            // Serve a 404 error page
            serve_error_page("404 Not Found", "error.html");
        }
        closesocket(newServerSocket);
        std::cout << "Closing browser response socket succesfully." << std::endl;
    }

    closesocket(serverSocket);
#ifdef _WIN32
    WSACleanup();
#endif
    std::cout << "Closing client request socket succesfully." << std::endl;
    std::cout << "Web server terminated successfully." << std::endl;
    return true;
};

bool lightweight_cpp_webserver::read_and_validate_headers(std::vector<std::string> &headers)
{
    // Read and validate headers
    char buff[30720] = {0};
    bytesReceived = recv(newServerSocket, buff, BUFFER_SIZE, 0);
    if (bytesReceived < 0)
    {
        std::cout << "Error: Could not read client request/possible client disconnect" << std::endl;
        return false;
    }
    std::cout << "Read client request successfully." << std::endl;

    // Security - Validate headers to prevent XSS attacks
    std::istringstream requestStream(buff);
    // read request line
    std::getline(requestStream, requestLine);
    // read headers
    std::cout << "Reading headers from client request" << std::endl;
    while (true)
    {
        std::string header;
        std::getline(requestStream, header);
        // break when we encounter an empty line indicating end of headers
        if (header.empty())
        {
            break;
        }
        headers.push_back(header);
    }
    // validate and sanitize headers to prevent XSS attacks
    for (const auto &header : headers)
    {
        // Perform header validation and sanitization logic here
        // You may use a library or implement your own logic to sanitize headers
        // For simplicity, we just print the headers in this example
        std::cout << "Header: " << header << std::endl;
        output_logs(header);
    }
    std::cout << "Client request headers logged successfully here: " + logPath << std::endl;
    // end security - XSS header validation sanitizing
    return true;
}

bool lightweight_cpp_webserver::accept_client_request()
{
#ifdef _WIN32
    newServerSocket = accept(serverSocket, (SOCKADDR *)&server, &server_len);
#else
    newServerSocket = accept(serverSocket, (struct sockaddr *)&server, &server_len);
#endif
    if (newServerSocket == INVALID_SOCKET)
    {
        std::cout << "Error: Unable to accept client request: \n"
                  << std::endl;
        closesocket(serverSocket);
#ifdef _WIN32
        WSACleanup();
#endif
        return false;
    }
    std::cout << "Accepted client request successfully." << std::endl;

    // Extract client IP address
    char clientIPAddressChar[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(server.sin_addr), clientIPAddressChar, INET_ADDRSTRLEN);
    clientIPAddress = std::string(clientIPAddressChar);
    std::cout << "Client IP address is: " << clientIPAddress << std::endl;

    return true;
}

void lightweight_cpp_webserver::output_logs(const std::string &header)
{
    std::string home_directory = "";

    // Determine the platform-specific file path separator
    std::string filepath_separator;
#ifdef _WIN32
    filepath_separator = '\\';
    home_directory = getenv("USERPROFILE");
#else
    filepath_separator = '/';
    home_directory = getenv("HOME");
#endif

    // Construct the log file path
    logPath = home_directory + filepath_separator + "logs.txt";

    // Get the current time
    auto currentTime = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

    // Open the log file in append mode
    std::ofstream outputFile(logPath, std::ios_base::app);

    // Check if the file is successfully opened
    if (outputFile.is_open())
    {
        // Write the timestamp, client IP, and header to the file
        outputFile << "[" << std::put_time(std::localtime(&currentTime), "%Y-%m-%d %H:%M:%S") << "] "
                   << "Client IP: " << clientIPAddress << " | "
                   << header << std::endl;

        // Close the file
        outputFile.close();
    }
    else
    {
        std::cerr << "Error: Unable to open log file for writing." << std::endl;
    }
};

void lightweight_cpp_webserver::send_response(int socket, const std::string &response)
{
    // Tracking if the size of the response sent to client when they view web server from web browser, matches total response size
    int bytesSent = 0;
    int totalBytesSent = 0;
    const char *responseBuffer = response.c_str(); // Pointer to the beginning of the response

    while (totalBytesSent < response.size())
    {
        /*
        Security - Prevent Buffer overflow attacks with Buffer size limit
        static cast std::min to ensure we don't send more than remaining bytes
        */
        bytesSent = send(socket, responseBuffer + totalBytesSent, static_cast<int>(std::min<int>(BUFFER_SIZE, response.size() - totalBytesSent)), 0);

        if (bytesSent <= 0)
        {
            std::cout << "Error: Couldn't send response" << std::endl;
            break; // Break out of the loop on send error
        }

        totalBytesSent += bytesSent;
    }

    if (totalBytesSent != response.size())
    {
        std::cout << "Error: Full response from server not sent to client. Byte size mismatch" << std::endl;
    }
    closesocket(socket);
}

std::string lightweight_cpp_webserver::get_requested_page(const std::string &url)
{
    // Example: If the URL is "/" e.g. "website-example.com/" or "127.0.0.1:8080/" return "index.html"
    if (url == "/")
    {
        return websiteIndexFile;
    }
    else if (!url.empty()) {
        // Example: If the URL is "downloads" e.g. "website-example.com/downloads" return "download.html"
        return url + ".html";
    }
    else
    {
        // If no specific page is matched, return the URL path relative to chosen website directory/"
        std::cout << "Page: " + url + " , Missing. Server default error.html page." << std::endl;
        return url.substr(1); // Remove the leading "/"
    }
}

std::string lightweight_cpp_webserver::read_static_html_file(std::string filePath)
{
    /*
        This code is for reading a index.html file and serving it to the clients browser
        It will use any linked files e.g. .css and .js for display/logic
        It will also serve links
    */
    std::cout << "Attempting to read file: " << filePath << std::endl;

    std::ifstream file(filePath);
    if (file)
    {
        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        return content;
    }
    else
    {
        std::cerr << "Error: Could not open file: " << filePath << std::endl;
        return "";
    }
}

void lightweight_cpp_webserver::handle_static_file_request(const std::string &requestedPage)
{
    std::cout << "Starting serving static webpage .html response to Client browser" << std::endl;
    std::string filePath = WebsiteFolderName + requestedPage;
    std::string fileContent = read_static_html_file(filePath);

    if (!fileContent.empty())
    {
        std::string response = "HTTP/1.1 200 OK\n"
                               "Content-Type: text/html\n"
                               "Content-Length: " +
                               std::to_string(fileContent.size()) + "\n\n" + fileContent;

        // Send the static file as the response
        send_response(newServerSocket, response);
        std::cout << "Sent response static webpage .html to Client browser successfully." << std::endl;
    }
}

void lightweight_cpp_webserver::serve_error_page(const std::string &statusCode, const std::string &errorPage)
{
    // Serve an error page
    std::string errorFilePath = WebsiteFolderName + errorPage;
    std::string errorFileContent = read_static_html_file(errorFilePath);

    if (!errorFileContent.empty())
    {
        std::string errorResponse = "HTTP/1.1 " + statusCode + "\n"
                                                               "Content-Type: text/html\n"
                                                               "Content-Length: " +
                                    std::to_string(errorFileContent.size()) + "\n\n" + errorFileContent;

        // Send the error page as the response
        send_response(newServerSocket, errorResponse);
        std::cout << "Finished sending response " + errorPage + " to Client browser." << std::endl;
        std::cout << "Closing client request socket." << std::endl;
    }
}

bool lightweight_cpp_webserver::ssl_initialise_context(const std::string &certFile, const std::string &keyFile)
{
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OPENSSL_init_ssl(0, NULL);

    // Create an SSL context
    ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ssl_ctx)
    {
        std::cerr << "Error: Failed to create SSL context." << std::endl;
        return false;
    }

    // Set options to disable outdated insecure SSLv2 and SSLv3
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    // Load certificate and private key
    if (SSL_CTX_use_certificate_file(ssl_ctx, certFile.c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        std::cerr << "Error: Failed to load certificate file: " << certFile << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, keyFile.c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        std::cerr << "Error: Failed to load private key file: " << keyFile << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Verify private key
    if (!SSL_CTX_check_private_key(ssl_ctx))
    {
        std::cerr << "Error: Private key does not match the certificate." << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }

    std::cout << "SSL webserver .cer and .key pair loaded successfully" << std::endl;

    return true;
}
bool lightweight_cpp_webserver::ssl_handshake()
{
    // Perform SSL handshake
    ssl = SSL_new(ssl_ctx);
    if (!ssl)
    {
        std::cerr << "Error: SSL handshake failed." << std::endl;
        return false;
    }

    SSL_set_fd(ssl, newServerSocket);
    if (SSL_accept(ssl) <= 0)
    {
        std::cerr << "Error: SSL handshake failed." << std::endl;
        return false;
    }

    std::cout << "SSL handshake successful." << std::endl;
    return true;
}
bool lightweight_cpp_webserver::ssl_read_request()
{
    // Read request over SSL connection
    char buff[30720] = {0};
    bytesReceived = SSL_read(ssl, buff, BUFFER_SIZE);
    if (bytesReceived <= 0)
    {
        std::cout << "Error: Could not read client request/possible client disconnect" << std::endl;
        return false;
    }
    std::cout << "Read client request successfully over SSL." << std::endl;

    // Process the request
    // ...

    return true;
}
bool lightweight_cpp_webserver::ssl_write_response(const std::string &response)
{
    // Write response over SSL connection
    int bytesSent = SSL_write(ssl, response.c_str(), response.size());
    if (bytesSent <= 0)
    {
        std::cerr << "Error: Couldn't send response over SSL." << std::endl;
        return false;
    }

    std::cout << "Sent response over SSL successfully." << std::endl;
    return true;
}
bool lightweight_cpp_webserver::ssl_shutdown()
{
    // Shutdown SSL connection
    SSL_shutdown(ssl);
    SSL_free(ssl);
    std::cout << "SSL connection shutdown successfully." << std::endl;
    return true;
}

void lightweight_cpp_webserver::signal_handler(int signum)
{
    // When Commands CTRL + C are entered the program will break, however as signal is registered
    // These additional commands will run, which are to clean up SSL.
    std::cout << "Termination signal received. Exiting program safely." << std::endl;
    if (serverInstance != nullptr && serverInstance->ssl_ctx != nullptr && serverInstance->ssl != nullptr)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        serverInstance->ssl_shutdown();
    }
    // Close the server socket
    closesocket(serverInstance->serverSocket);

#ifdef _WIN32
    // Cleanup Winsock if on Windows
    WSACleanup();
#endif
}

void lightweight_cpp_webserver::default_string_initialisation_inputs(const std::string& defaultValue)
{
    std::string userInput;
    std::getline(std::cin, userInput);
    if (!userInput.empty())
    {
        if (defaultValue == "webserverIPAddress") {
            set_IP_address(userInput);
        }
        else if (defaultValue == "WebsiteFolderName") {
            set_website_directory(userInput);
        }
        else if (defaultValue == "websiteIndexFile") {
            set_website_index(userInput);
        }
        else if (defaultValue == "webserverPortNumber") {
            set_port_number(std::stoi(userInput));
        }
    }
    std::cin.clear();
}

