#pragma once
#include <windows.h>
#include <wincrypt.h>
#include <vector>
#include <string>
#include <iostream>

#pragma comment(lib, "advapi32.lib")

class RSA {
private:
    HCRYPTPROV hProv;
    HCRYPTKEY hPublicKey;
    HCRYPTKEY hPrivateKey;

public:
    RSA() : hProv(NULL), hPublicKey(NULL), hPrivateKey(NULL) {
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET);
        }
    }

    ~RSA() {
        if (hPublicKey) CryptDestroyKey(hPublicKey);
        if (hPrivateKey) CryptDestroyKey(hPrivateKey);
        if (hProv) CryptReleaseContext(hProv, 0);
    }

    bool GenerateKeyPair() {
        if (!CryptGenKey(hProv, CALG_RSA_KEYX, CRYPT_EXPORTABLE, &hPrivateKey)) {
            std::cerr << "CryptGenKey failed: " << GetLastError() << std::endl;
            return false;
        }

        DWORD publicKeyLen = 0;
        CryptExportKey(hPrivateKey, NULL, PUBLICKEYBLOB, 0, NULL, &publicKeyLen);

        std::vector<BYTE> publicKeyBlob(publicKeyLen);
        if (!CryptExportKey(hPrivateKey, NULL, PUBLICKEYBLOB, 0, publicKeyBlob.data(), &publicKeyLen)) {
            std::cerr << "CryptExportKey failed: " << GetLastError() << std::endl;
            return false;
        }

        if (!CryptImportKey(hProv, publicKeyBlob.data(), publicKeyBlob.size(), 0, 0, &hPublicKey)) {
            std::cerr << "CryptImportKey failed: " << GetLastError() << std::endl;
            return false;
        }

        return true;
    }

    std::vector<BYTE> EncryptAESKey(const std::vector<BYTE>& aesKey) {
        std::vector<BYTE> empty;
        if (!hPublicKey) {
            std::cerr << "RSA: No public key available" << std::endl;
            return empty;
        }

        DWORD keySize = aesKey.size();
        DWORD encryptedSize = 0;

        CryptEncrypt(hPublicKey, 0, TRUE, 0, NULL, &keySize, 0);

        std::vector<BYTE> encryptedKey(keySize + 64);
        memcpy(encryptedKey.data(), aesKey.data(), aesKey.size());

        DWORD dataSize = aesKey.size();
        if (!CryptEncrypt(hPublicKey, 0, TRUE, 0, encryptedKey.data(), &dataSize, encryptedKey.size())) {
            DWORD err = GetLastError();
            std::cerr << "RSA Encrypt failed: " << err << std::endl;
            return empty;
        }

        encryptedKey.resize(dataSize);
        std::cout << "RSA: Encrypted key size: " << encryptedKey.size() << std::endl;
        return encryptedKey;
    }

    std::vector<BYTE> DecryptAESKey(const std::vector<BYTE>& encryptedAESKey) {
        std::vector<BYTE> empty;
        if (!hPrivateKey) {
            std::cerr << "RSA: No private key available" << std::endl;
            return empty;
        }

        DWORD keySize = encryptedAESKey.size();
        std::vector<BYTE> decryptedKey = encryptedAESKey;

        if (!CryptDecrypt(hPrivateKey, 0, TRUE, 0, decryptedKey.data(), &keySize)) {
            DWORD err = GetLastError();
            std::cerr << "RSA Decrypt failed: " << err << std::endl;
            return empty;
        }

        decryptedKey.resize(keySize);
        return decryptedKey;
    }

    // Export public key to embed in encryptor
    std::vector<BYTE> ExportPublicKey() {
        std::vector<BYTE> empty;
        if (!hPublicKey) return empty;

        DWORD blobSize = 0;
        CryptExportKey(hPublicKey, NULL, PUBLICKEYBLOB, 0, NULL, &blobSize);

        std::vector<BYTE> keyBlob(blobSize);
        if (!CryptExportKey(hPublicKey, NULL, PUBLICKEYBLOB, 0, keyBlob.data(), &blobSize)) {
            return empty;
        }
        return keyBlob;
    }

    // Export private key to embed in decryptor
    std::vector<BYTE> ExportPrivateKey() {
        std::vector<BYTE> empty;
        if (!hPrivateKey) return empty;

        DWORD blobSize = 0;
        CryptExportKey(hPrivateKey, NULL, PRIVATEKEYBLOB, 0, NULL, &blobSize);

        std::vector<BYTE> keyBlob(blobSize);
        if (!CryptExportKey(hPrivateKey, NULL, PRIVATEKEYBLOB, 0, keyBlob.data(), &blobSize)) {
            return empty;
        }
        return keyBlob;
    }

    // import public key (for encryptor)
    bool ImportPublicKey(const std::vector<BYTE>& publicKeyBlob) {
        if (hPublicKey) {
            CryptDestroyKey(hPublicKey);
            hPublicKey = NULL;
        }
        return CryptImportKey(hProv, publicKeyBlob.data(), publicKeyBlob.size(), 0, 0, &hPublicKey);
    }

    // import private key (for decryptor)
    bool ImportPrivateKey(const std::vector<BYTE>& privateKeyBlob) {
        if (hPrivateKey) {
            CryptDestroyKey(hPrivateKey);
            hPrivateKey = NULL;
        }
        return CryptImportKey(hProv, privateKeyBlob.data(), privateKeyBlob.size(), 0, 0, &hPrivateKey);
    }
};
