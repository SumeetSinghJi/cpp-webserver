/*
    Author: Sumeet Singh
    Dated: 22/01/2024
    Minimum C++ Standard: C++11
*/

#include "headers/lightweight_cpp_webserver.hpp" // function and class declarations

/* TO DO
 * Enable https using OpenSSL (SSL/TLS) create a cert
 * Content Security Policy (CSP)
 * use #include <boost/asio.hpp> for Asynchronous concurrent connctions instances of web server:
 * SANDBOX - Possibly expand using enet to create a multiplayer capable server
 */

// Constructor definition
lightweight_cpp_webserver::lightweight_cpp_webserver(const std::string &ipAddress, int portNumber)
    : BUFFER_SIZE(30720), clientIPAddress(ipAddress), clientPortNumber(portNumber)
{
    // constructor logic here
}

void lightweight_cpp_webserver::setIPAddress(const std::string &ipAddress)
{
    if (isValidIPAddress(ipAddress))
    {
        this->clientIPAddress = ipAddress;
    }
    else
    {
        std::cout << "Error: Invalid IP address range. Must be private address in class A (10.), B (172.16.31.) or C (192.168.)" << std::endl;
    }
}

void lightweight_cpp_webserver::setPortNumber(int portNumber)
{
    if (isValidPortAddress(portNumber))
    {
        this->clientPortNumber = portNumber;
    }
    else
    {
        std::cout << "Error: Invalid port range. Must be < 8080 * > 8090" << std::endl;
    }
}

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
    server.sin_addr.s_addr = inet_addr(clientIPAddress.c_str());
    server.sin_port = htons(clientPortNumber);
    server_len = sizeof(server);

    if (bind(serverSocket, (SOCKADDR *)&server, server_len) != 0)
    {
        std::cout << "Error: Could not bind address: " << clientIPAddress << ":" << clientPortNumber << " to web socket" << std::endl;
    }

    // listen for address
    if (listen(serverSocket, 20) != 0)
    {
        std::cout << "Error: Could not listen to anything on address: " << clientIPAddress << ":" << clientPortNumber << std::endl;
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
            std::cout << "Starting serving static webpage .html response to Client browser" << std::endl;
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
    return true;
}

bool lightweight_cpp_webserver::isValidIPAddress(const std::string &ipAddress)
{
    // Security - Input validation
    // Split the IP address into octets
    std::vector<int> octets;
    std::istringstream ss(ipAddress);
    std::string octet;
    while (std::getline(ss, octet, '.'))
    {
        octets.push_back(std::stoi(octet));
    }

    // Check if the IP address falls within the specified ranges
    if (octets.size() == 4)
    {
        if ((octets[0] == 10) ||
            (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) ||
            (octets[0] == 192 && octets[1] == 168))
        {
            return true;
        }
    }

    return false;
};

bool lightweight_cpp_webserver::isValidPortAddress(int &portNumber)
{
    // Security - Input validation
    if (portNumber >= 8080 && portNumber <= 8090)
    {
        return true;
    }
    return false;
};

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
        // Write the timestamp and header to the file
        outputFile << "[" << std::put_time(std::localtime(&currentTime), "%Y-%m-%d %H:%M:%S") << "] " << header << std::endl;

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
    // server index.html on root: 172.0.0.1:8080
    if (url == "/")
    {
        return "index.html";
    }
    else if (url == "/homepage")
    {
        // Example: If the URL is "/homepage", return "homepage.html"
        return "homepage.html";
    }
    // Add more conditions based on your URL mapping
    // ...
    else
    {
        // If no specific page is matched, return the URL path relative to "website/"
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
    std::string filePath = "website/" + requestedPage;
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
    std::string errorFilePath = "website/" + errorPage;
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
