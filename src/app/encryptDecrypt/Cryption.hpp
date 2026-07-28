#ifndef CRYPTION_HPP
#define CRYPTION_HPP

#include <filesystem>
#include <string>

bool initializeCrypto();

bool encryptFile(const std::filesystem::path &inputPath, const std::filesystem::path &outputPath, const std::string &password);

bool decryptFile(const std::filesystem::path &inputPath, const std::filesystem::path &outputPath, const std::string &password);

#endif
