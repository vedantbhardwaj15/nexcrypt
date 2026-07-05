#include <algorithm>
#include <cctype>
#include <filesystem>
#include <iostream>
#include <string>

#include "./src/app/encryptDecrypt/Cryption.hpp"

namespace fs = std::filesystem;

namespace {
std::string toUpper(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::toupper(ch));
    });
    return value;
}

bool hasNexExtension(const fs::path &path) {
    return path.extension() == ".nex";
}

fs::path encryptedPathFor(const fs::path &path) {
    return fs::path(path.string() + ".nex");
}

fs::path decryptedPathFor(const fs::path &path) {
    if (hasNexExtension(path)) {
        fs::path output = path;
        output.replace_extension("");
        return output;
    }

    return fs::path(path.string() + ".decrypted");
}

bool processFile(const fs::path &filePath,
                 const std::string &action,
                 const std::string &password) {
    if (action == "ENCRYPT") {
        if (hasNexExtension(filePath)) {
            std::cout << "Skipping already encrypted file: " << filePath << std::endl;
            return true;
        }

        const fs::path outputPath = encryptedPathFor(filePath);
        std::cout << "Encrypting: " << filePath << " -> " << outputPath << std::endl;
        return encryptFile(filePath.string(), outputPath.string(), password);
    }

    if (!hasNexExtension(filePath)) {
        std::cout << "Skipping non-.nex file: " << filePath << std::endl;
        return true;
    }

    const fs::path outputPath = decryptedPathFor(filePath);
    std::cout << "Decrypting: " << filePath << " -> " << outputPath << std::endl;
    return decryptFile(filePath.string(), outputPath.string(), password);
}
}

int main() {
    std::string pathInput;
    std::string action;
    std::string password;

    std::cout << "Enter file or directory path:" << std::endl;
    std::getline(std::cin, pathInput);

    std::cout << "Enter action (ENCRYPT/DECRYPT):" << std::endl;
    std::getline(std::cin, action);
    action = toUpper(action);

    if (action != "ENCRYPT" && action != "DECRYPT") {
        std::cerr << "Invalid action. Use ENCRYPT or DECRYPT." << std::endl;
        return 1;
    }

    std::cout << "Enter password:" << std::endl;
    std::getline(std::cin, password);

    if (password.empty()) {
        std::cerr << "Password cannot be empty." << std::endl;
        return 1;
    }

    const fs::path target(pathInput);

    try {
        if (fs::is_regular_file(target)) {
            return processFile(target, action, password) ? 0 : 1;
        }

        if (fs::is_directory(target)) {
            bool allSucceeded = true;
            for (const auto &entry : fs::recursive_directory_iterator(target)) {
                if (!entry.is_regular_file()) {
                    continue;
                }

                if (!processFile(entry.path(), action, password)) {
                    allSucceeded = false;
                }
            }

            return allSucceeded ? 0 : 1;
        }

        std::cerr << "Path does not exist or is not a regular file/directory." << std::endl;
        return 1;
    } catch (const fs::filesystem_error &ex) {
        std::cerr << "Filesystem error: " << ex.what() << std::endl;
        return 1;
    }
}
