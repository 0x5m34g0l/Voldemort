#pragma once
#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

class AES {
private:
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    std::vector<BYTE> key;

public:
    AES() : hProv(NULL), hKey(NULL) {
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET);
        }
    }

    ~AES() {
        if (hKey) CryptDestroyKey(hKey);
        if (hProv) CryptReleaseContext(hProv, 0);
    }

    std::vector<BYTE> GenerateKey() {
        key.resize(32);
        if (!CryptGenRandom(hProv, 32, key.data())) {
            std::cerr << "CryptGenRandom failed: " << GetLastError() << std::endl;
            return std::vector<BYTE>();
        }
        return key;
    }

    bool SetKey(const std::vector<BYTE>& keyBytes) {
        if (keyBytes.size() != 32) {
            std::cerr << "[-] Invalid key size: " << keyBytes.size() << " (must be 32)" << std::endl;
            return false;
        }

        key = keyBytes;

        struct {
            BLOBHEADER header;
            DWORD keySize;
            BYTE keyData[32];
        } keyBlob;

        keyBlob.header.bType = PLAINTEXTKEYBLOB;
        keyBlob.header.bVersion = CUR_BLOB_VERSION;
        keyBlob.header.reserved = 0;
        keyBlob.header.aiKeyAlg = CALG_AES_256;
        keyBlob.keySize = 32;
        memcpy(keyBlob.keyData, keyBytes.data(), 32);

        if (hKey) {
            CryptDestroyKey(hKey);
            hKey = NULL;
        }

        if (!CryptImportKey(hProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey)) {
            DWORD err = GetLastError();
            std::cerr << "CryptImportKey failed: " << err << std::endl;
            return false;
        }

        return true;
    }

    bool EncryptFile(const std::string& filename) {
        if (!hKey) {
            if (!SetKey(key)) return false;
        }

        std::ifstream file(filename, std::ios::binary | std::ios::ate);
        if (!file) return false;

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        std::vector<BYTE> buffer(size);
        if (!file.read((char*)buffer.data(), size)) {
            return false;
        }
        file.close();

        DWORD dataSize = buffer.size();
        DWORD encryptedSize = dataSize + 16;

        std::vector<BYTE> encrypted(encryptedSize);
        memcpy(encrypted.data(), buffer.data(), dataSize);

        if (!CryptEncrypt(hKey, 0, TRUE, 0, encrypted.data(), &dataSize, encryptedSize)) {
            DWORD err = GetLastError();
            std::cerr << "CryptEncrypt failed for " << filename << ": " << err << std::endl;
            return false;
        }

        std::ofstream out(filename, std::ios::binary | std::ios::trunc);
        if (!out.write((char*)encrypted.data(), dataSize)) {
            return false;
        }

        return true;
    }

    bool DecryptFile(const std::string& filename) {
        if (!hKey) {
            std::cerr << "[-] No key set for " << filename << std::endl;
            if (!SetKey(key)) return false;
        }

        // Read file
        std::ifstream file(filename, std::ios::binary | std::ios::ate);
        if (!file) {
            std::cerr << "[-] Cannot open file: " << filename << std::endl;
            return false;
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        std::vector<BYTE> buffer(size);
        if (!file.read((char*)buffer.data(), size)) {
            std::cerr << "[-] Cannot read file: " << filename << std::endl;
            return false;
        }
        file.close();

        DWORD dataSize = buffer.size();
        std::cout << "[-] Decrypting " << filename << " (" << dataSize << " bytes)" << std::endl;

        // Try to decrypt
        if (!CryptDecrypt(hKey, 0, TRUE, 0, buffer.data(), &dataSize)) {
            DWORD err = GetLastError();
            std::cerr << "[-] CryptDecrypt failed for " << filename << ": Error " << err << std::endl;

            // Print Windows error message
            LPSTR messageBuffer = nullptr;
            FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
            std::cerr << "[-] Error message: " << messageBuffer << std::endl;
            LocalFree(messageBuffer);

            return false;
        }

        // Write back
        std::ofstream out(filename, std::ios::binary | std::ios::trunc);
        if (!out.write((char*)buffer.data(), dataSize)) {
            std::cerr << "[-] Cannot write file: " << filename << std::endl;
            return false;
        }

        std::cout << "[+] Successfully decrypted: " << filename << std::endl;
        return true;
    }

    std::vector<BYTE> GetKey() const { return key; }
};
