#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <iostream>
#include <string>
#include <fstream>
#include "desBlockModes.h"
#include "hmac.h"

//network
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

// Need to link with Ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "3069"

using std::cin;
using std::cout;
using std::endl;
using std::string;
string decrypt(string s,const int &mode, const string &key, const string &IV, const string &counter);
int initSockets(SOCKET &ClientSocket);
int cleanUp(SOCKET &ClientSocket);

int __cdecl main(void)
{
    cout << "Please connect the sender and choose mode.\n";
    SOCKET ClientSocket = INVALID_SOCKET;
    int iResult = initSockets(ClientSocket);
    if (iResult)
    {
        return iResult;
    }
    cout << "receiver started.\n\n";
    char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;
    // Receive until the peer shuts down the connection
    do
    {
        iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
        if (iResult > 0)
        {
            string message(recvbuf);
            string hmacHex = message.substr(iResult - 40, 40);
            message = message.substr(0, iResult - 40);
            cout << "received message " << message << "\nWith hmac =" << hmacHex << endl;

            //read file each time (so that file can be changed during runtime)
            int mode;
            string key, IV, counter , hmacKey;
            std::ifstream fs("config.txt");
            fs >> mode >> key >> IV >> counter >>hmacKey;
            fs.close();

            string hmacHex2 = hmac(message, hmacKey);
            if (hmacHex == hmacHex2)
            {
                cout << "Correct Hmac! Cipher text is correct" << endl;
            }
            else
            {
                cout << "Wrong Hmac!, calculated hmac= " << hmacHex2<< endl;
            }
            message = decrypt(message, mode, key, IV, counter);
                cout << "decrypted message: " << message << "\n\n";
        }
        else if (iResult == 0)
            printf("Connection closing...\n");
        else
        {
            printf("recv failed with error: %d\n", WSAGetLastError());
            closesocket(ClientSocket);
            WSACleanup();
            return 1;
        }

    } while (iResult > 0);

    iResult = cleanUp(ClientSocket);
    if (iResult)
    {
        return iResult;
    }

    return 0;
}

string decrypt(string s, const int &mode, const string &key, const string &IV, const string &counter)
{
    switch (mode)
    {
    case ECB:
        return ECB_D(s, key);
    case CBC:
        return CBC_D(s, key, IV);
    case CFB:
        return CFB_D(s, key, IV);
    case CTR:
        return CTR_ED(s, key, counter);
    default:
        break;
    }
    return "Mode Error";
}

int initSockets(SOCKET &ClientSocket)
{
    WSADATA wsaData;
    SOCKET ListenSocket = INVALID_SOCKET;
    struct addrinfo *result = NULL;
    struct addrinfo hints;

    // Initialize Winsock
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0)
    {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (iResult != 0)
    {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Create a SOCKET for connecting to server
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET)
    {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // Setup the TCP listening socket
    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR)
    {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR)
    {
        printf("listen failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    // Accept a client socket
    ClientSocket = accept(ListenSocket, NULL, NULL);
    if (ClientSocket == INVALID_SOCKET)
    {
        printf("accept failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    // No longer need server socket
    closesocket(ListenSocket);
    return 0;
}

int cleanUp(SOCKET &ClientSocket)
{
    // shutdown the connection since we're done
    int iResult = shutdown(ClientSocket, SD_SEND);
    if (iResult == SOCKET_ERROR)
    {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(ClientSocket);
        WSACleanup();
        return 1;
    }

    // cleanup
    closesocket(ClientSocket);
    WSACleanup();
    return 0;
}