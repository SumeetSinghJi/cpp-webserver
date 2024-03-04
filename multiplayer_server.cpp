/*
    Author: Sumeet Singh
    Dated: 22/01/2024
    Minimum C++ Standard: C++11
    Purpose: Implementation file for starting the web server with SSL support
    License: MIT License
    Description: Web server,
    build from this Youtube tutorial: https://www.youtube.com/watch?v=14ZFKR-tFMU&list=PLhnN2F9NiVmAMn9iGB_Rtjs3aGef3GpSm&index=3
*/

/* TO DO
1. add SSL using OpenSSL key cert
*/

#include <iostream>
#include <string>
#include <chrono>  // for time output
#include <iomanip> // for put_time to cout time_t variable

#ifdef _WIN32
#include <winsock2.h>
#include <WS2tcpip.h>
#include <windows.h>
#else
#include <sys/socket.h>
#include <arpa.inet.h>
#include <unistd.h>
#endif

struct sockaddr_in webServer;
int webServerSocket;                   // listener socket
int webServerPort = 9909;              // this local web server port
std::string webServerIP = "127.0.0.1"; // this local web server IP address
int webserverFunctionReturnValue = 0;
fd_set fr, fw, fe; // file/socket descriptors to read to network/write to network/errors
int nMaxFd;
int arrayClientConnections[5]; // handle max 5 clients
std::string clientIPAddress = "";

void process_new_message(int clientSocket)
{
    std::cout << "Processing the new message for client socket: " << clientSocket << std::endl;
    char buff[256 + 1] = {
        0,
    };
    int webserverFunctionReturnValue = recv(clientSocket, buff, 256, 0);
    if (webserverFunctionReturnValue < 0)
    {
        std::cout << "Error processing client message: " << std::endl;
        closesocket(clientSocket);
        for (int x = 1; x < 5; x++)
        {
            if (arrayClientConnections[x] == clientSocket)
            {
                arrayClientConnections[x] = 0;
                break;
            }
        }
    }
    else
    {
        std::cout << "Message received from client is: " << std::endl;
        // send response to the client
        send(clientSocket, "Processed your request", 23, 0);
        std::cout << "*******************************************" << std::endl;
    }
}

void process_client_request()
{
    // Get the current time
    auto currentTime = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::cout << std::put_time(std::localtime(&currentTime), "%Y-%m-%d %H-%M-%S") << std::endl;

    // Extract client IP address
    char clientIPAddressChar[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(webServer.sin_addr), clientIPAddressChar, INET_ADDRSTRLEN);
    clientIPAddress = std::string(clientIPAddressChar);
    std::cout << "Client IP address is: " << clientIPAddress << std::endl;

    // new client connection request
    if (FD_ISSET(webServerSocket, &fr))
    {
        int requestLength = sizeof(struct sockaddr);
        int clientSocket = accept(webServerSocket, NULL, &requestLength);
        if (clientSocket > 0)
        {
            // If you accept a client request, you can respond to client on that same file read descriptor "fr"
            // so the fr becomes the client/server connection found in the client fd_set
            int x;
            for (x = 0; x < 5; x++)
            {
                if (arrayClientConnections[x] == 0)
                {
                    arrayClientConnections[x] = clientSocket;
                    send(clientSocket, "Webserver received client request successfully", 47, 0);
                    break;
                }
            }
            if (x == 5)
            {
                std::cout << "No more space for a new client connection. Max is: " << sizeof(arrayClientConnections) << std::endl;
            }
        }
    }
    else // Client already established socket connection above, then process the next message
    {
        for (int x = 0; x < 5; x++)
        {
            if (FD_ISSET(arrayClientConnections[x], &fr))
            {
                // Got the new message from the client
                // Just recev new message
                // just queue message for new worker of webserver to full fill
                process_new_message(arrayClientConnections[x]);
            }
        }
    }
}

int main()
{
    std::cout << "\nStep 1: Initialise WSA" << std::endl;
    // Initialise the WSA variables
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) < 0)
    {
        std::cout << "Error: WSA Initialisation failed" << std::endl;
        WSACleanup();
        return 1;
    }
    else
    {
        std::cout << "WSA initialised successfully" << std::endl;
    }

    std::cout << "\nStep 2: Initialise the socket" << std::endl;
    // AF_INET =
    // SOCK_STREAM = Connection oriented (TCP)
    // IPPROTO_TCP = Use TCP as protocol
    webServerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (webServerSocket < 0)
    {
        std::cout << "Error: Socket Initialisation failed; socket:" << webServerSocket << " not opened" << std::endl;
        WSACleanup();
        return 1;
    }
    else
    {
        std::cout << "Socket: " << webServerSocket << " opened successfully" << std::endl;
    }

    std::cout << "\nStep 3: Initialise this web server for sockaddr structure/variables" << std::endl;

    webServer.sin_family = AF_INET;
    webServer.sin_port = htons(webServerPort);
    webServer.sin_addr.s_addr = inet_addr(webServerIP.c_str()); // inet_addr() converts string to byte order for .s_addr
    memset(&(webServer.sin_zero), 0, 8);
    if (webServer.sin_addr.s_addr == INADDR_NONE)
    {
        std::cout << "Error: Failed to initialise local web server with IP address" << std::endl;
        WSACleanup();
        return 1;
    }
    else
    {
        std::cout << "Successfully initialised this local web server with IP address: " << webServerIP << std::endl;
    }

    // On server restart/failure this code SO_REUSEADDR will rebind the socket back to webserver]
    int webserverOptVal = 0;
    int webserverOptLen = sizeof(webserverOptVal);
    webserverFunctionReturnValue = setsockopt(webServerSocket, SOL_SOCKET, SO_REUSEADDR, (const char *)&webserverOptVal, webserverOptLen);
    if (webserverFunctionReturnValue)
    {
        std::cout << "Error: Failed to initialise setsockopt()" << std::endl;
        WSACleanup();
        return 1;
    }
    else
    {
        std::cout << "Successfully initialised setsockopt()" << std::endl;
    }

    std::cout << "\nStep 4: Bind the socket to this local web server port" << std::endl;
    webserverFunctionReturnValue = bind(webServerSocket, (sockaddr *)&webServer, sizeof(sockaddr));
    if (webserverFunctionReturnValue < 0)
    {
        std::cout << "Error: Failed to bind socket to local web server port" << std::endl;
        WSACleanup();
        return 1;
    }
    else
    {
        std::cout << "Successfully binded socket to local web server port" << std::endl;
    }

    std::cout << "\nStep 5: Listen for client requests in queue" << std::endl;
    webserverFunctionReturnValue = listen(webServerSocket, 5); // queue of requests is max 5 in active
    if (webserverFunctionReturnValue < 0)
    {
        std::cout << "Error: Failed to start listen() on local web server port" << std::endl;
        WSACleanup();
        return 1;
    }
    else
    {
        std::cout << "Successfully started listen() on local web server port" << std::endl;
    }

    std::cout << "\nStep 6: Keep waiting for new requests and proceed as per request" << std::endl;

    nMaxFd = webServerSocket;
    struct timeval timeoutValue;
    timeoutValue.tv_sec = 1;
    timeoutValue.tv_usec = 0;

    while (1)
    {
        FD_ZERO(&fr);
        FD_ZERO(&fw);
        FD_ZERO(&fe);

        FD_SET(webServerSocket, &fr);
        FD_SET(webServerSocket, &fe);

        for (int x = 0; x > 5; x++)
        {
            if (arrayClientConnections[x] != 0)
            {
                // will contain new socket descriptor to send and recieve messages with the client
                FD_SET(arrayClientConnections[x], &fr);
                // These sockets can also throw some errors
                FD_SET(arrayClientConnections[x], &fe);
            }
        }

        // Wait one second to see if file descriptors on sockets contain anything
        webserverFunctionReturnValue = select(nMaxFd + 1, &fr, &fr, &fe, &timeoutValue);

        if (webserverFunctionReturnValue > 0) // if number > 0 then their is a socket descriptor with something in it/to do
        {
            // connection/communication request made to local web server
            std::cout << "Connection made, processing data now..." << std::endl;
            process_client_request();
        }
        else if (webserverFunctionReturnValue == 0)
        {
            // no connection/communication request made to local web server OR nothing to read in file descriptor on port
            std::cout << "No file descriptors on port: " << webServerPort << std::endl;
        }
        else
        {
            //  file descriptor read failed
            std::cout << "Error: Failed to reset file descriptor: " << webServerPort << std::endl;
            WSACleanup();
            return 1;
        }
    }

    WSACleanup();
    return 0;
}
