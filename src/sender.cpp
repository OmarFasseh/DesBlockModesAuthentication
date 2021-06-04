#define WIN32_LEAN_AND_MEAN

#include <iostream>
#include <string>
#include <fstream>
#include <time.h>
#include <sstream>
#include "desBlockModes.h"
#include "hmac.h"

//network
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")
#pragma comment(lib, "AdvApi32.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "3069"

using std::cin;
using std::cout;
using std::endl;
using std::string;

void writeConfig(int &mode, string &key, string &IV, string &counter, string &hmacKey);
string encrypt(int mode, string s, const string &key, const string &IV, const string &counter);
int initSockets(SOCKET &ConnectSocket);
int cleanUp(SOCKET &ConnectSocket);

int __cdecl main()
{
    srand((unsigned)time(NULL));
    int mode;
    // string key = "133457799BBCDFF1";
    // string IV = "133457799BBCDFF1";
    // string counter = "1478523691abcdef";
    string key = "";
    string hmacKey = "";
    string IV = "";
    string counter = "";
    std::stringstream stream;
    unsigned int x;
    for (int i = 0; i < 16; i++)
    {
        x = rand() % 16;
        stream.str(std::string());
        stream << std::hex << x;
        key += stream.str();

        x = rand() % 16;
        stream.str(std::string());
        stream << std::hex << x;
        IV += stream.str();

        x = rand() % 16;
        stream.str(std::string());
        stream << std::hex << x;
        counter += stream.str();
    }
    int keySize = rand() % 63 + 1; //make sure it has at least size of 1 
    for (int i = 0; i < keySize; i++)
    {
        x = rand() % 16;
        stream.str(std::string());
        stream << std::hex << x;
        hmacKey += stream.str();
    }

    cout << "Generated key = " << key << "\nGenerated IV=" << IV << "\nGenerated Counter=" << counter << "\nhmacKey=" << hmacKey << endl;

    writeConfig(mode, key, IV, counter, hmacKey);

    SOCKET ConnectSocket = INVALID_SOCKET;
    int iResult = initSockets(ConnectSocket);
    if (iResult)
    {
        return iResult;
    }

    char sendbuf[DEFAULT_BUFLEN];
    cout << "\nEnter messages to send, and \"exit\" to end" << endl;
    string message;
    string hmacHex;
    getline(cin, message);
    while (message != "exit")
    {
        if (message.size())
        {
            message = encrypt(mode, message, key, IV, counter);
            hmacHex = hmac(message, hmacKey); //TODO: might want to use another key
            cout << "message after encryption" << message << endl
                 << "HMAC-SHA1 after encrpytion: " << hmacHex << endl
                 << endl;
            message = message + hmacHex;
            iResult = send(ConnectSocket, message.c_str(), message.size(), 0);
            if (iResult == SOCKET_ERROR)
            {
                printf("send failed with error: %d\n", WSAGetLastError());
                closesocket(ConnectSocket);
                WSACleanup();
                return 1;
            }
        }
        getline(cin, message);
    }

    iResult = cleanUp(ConnectSocket);
    if (iResult)
    {
        return iResult;
    }

    return 0;
}
string encrypt(int mode, string s, const string &key, const string &IV, const string &counter)
{
    switch (mode)
    {
    case ECB:
        return ECB_E(s, key);
    case CBC:
        return CBC_E(s, key, IV);
    case CFB:
        return CFB_E(s, key, IV);
    case CTR:
        return CTR_ED(s, key, counter);
    default:
        break;
    }
    return "";
}

void writeConfig(int &mode, string &key, string &IV, string &counter, string &hmacKey)
{
    cout << "Choose mode: (1~4) \n1) Electronic Codebook (ECB)"
         << "\n2) Cipher Block Chaining (CBC)"
         << "\n3) Cipher Feedback (CFB)"
         << "\n4) Counter (CTR)\n";

    cin >> mode;
    //enum "modes" is declared in desBlockModes.h
    while (mode > 4 || mode < 1)
    {
        cout << "please enter a valid mode (1~4): ";
        cin >> mode;
    }
    std::ofstream fs("config.txt");
    fs << mode << " " << key << " " << IV << " " << counter << " " << hmacKey;
    fs << "\nmode    key             IV             Counter             hmac";

    fs.close();
}

int initSockets(SOCKET &ConnectSocket)
{
    WSADATA wsaData;
    struct addrinfo *result = NULL,
                    *ptr = NULL,
                    hints;
    int iResult;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0)
    {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    iResult = getaddrinfo("localhost", DEFAULT_PORT, &hints, &result);
    if (iResult != 0)
    {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Attempt to connect to an address until one succeeds
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
    {

        // Create a SOCKET for connecting to server
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
                               ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET)
        {
            printf("socket failed with error: %ld\n", WSAGetLastError());
            WSACleanup();
            return 1;
        }

        // Connect to server.
        iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR)
        {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET)
    {
        printf("Unable to connect to server!\n");
        WSACleanup();
        return 1;
    }
    return 0;
}

int cleanUp(SOCKET &ConnectSocket)
{
    // shutdown the connection since no more data will be sent
    int iResult = shutdown(ConnectSocket, SD_SEND);
    if (iResult == SOCKET_ERROR)
    {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    // cleanup
    closesocket(ConnectSocket);
    WSACleanup();
    return 0;
}