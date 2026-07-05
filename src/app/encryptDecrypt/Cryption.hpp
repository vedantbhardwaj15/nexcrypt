#ifndef CRYPTION_HPP
#define CRYPTION_HPP

#include <string>

bool initializeCrypto();

bool encryptFile(const std::string &inputPath, const std::string &outputPath, const std::string &password);

bool decryptFile(const std::string &inputPath, const std::string &outputPath, const std::string &password);

#endif
