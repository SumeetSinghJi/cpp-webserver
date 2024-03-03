/*
    Author: Sumeet Singh
    Dated: 22/01/2024
    Minimum C++ Standard: C++11
    Purpose: Simulated Client browser program to connect to web server on variables: clientIP/clientPort
    License: MIT License
    Description: 
    build from this Youtube tutorial: https://www.youtube.com/watch?v=14ZFKR-tFMU&list=PLhnN2F9NiVmAMn9iGB_Rtjs3aGef3GpSm&index=3
*/

#include <iostream>
#include <string>
#include <chrono> // program sleep 1 second while attempting to connect to web server
#include <thread> // program sleep 1 second while attempting to connect to web server

#ifdef _WIN32
#include <winsock2.h>
#include <WS2tcpip.h>
#include <windows.h>
#else
#include <sys/socket.h>
#include <arpa.inet.h>
#include <unistd.h>
#endif

struct sockaddr_in clientServer;
int clientSocket;
int clientPort = 9909;
std::string clientIP = "127.0.0.1";
int clientFunctionReturnValue = 0;
char buff[255] = {
    0,
};

int main()
{

    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) < 0)
    {
        std::cout << "Error: Failed to initialise WSA" << std::endl;
        WSACleanup();
        return 1;
    }

    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (clientSocket < 0)
    {
        std::cout << "Error: Socket Initialisation failed; socket:" << clientSocket << " not opened" << std::endl;
        WSACleanup();
        return 1;
    }

    clientServer.sin_family = AF_INET;
    clientServer.sin_port = htons(clientPort);
    clientServer.sin_addr.s_addr = inet_addr(clientIP.c_str());
    memset(&clientServer.sin_zero, 0, 8);

    while(true) {
        clientFunctionReturnValue = connect(clientSocket, (struct sockaddr *)&clientServer, sizeof(clientServer));

        if (clientFunctionReturnValue < 0)
        {
            std::cout << "Error: Connection failed" << std::endl;
            // WSACleanup();
            // return 1;
        }
        else
        {
            std::cout << "Connected to the web server" << std::endl;
            recv(clientSocket, buff, 255, 0);
            std::cout << "Press any key to see message received from server" << std::endl;
            std::cin.get();
            std::cout << buff << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    

    return 0;
}