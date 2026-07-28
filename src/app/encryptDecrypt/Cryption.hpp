#ifndef CRYPTION_HPP
#define CRYPTION_HPP

#include <filesystem>
#include <string>
#include <sodium.h>

bool initializeCrypto();

bool deriveKeyFromPassword(const std::string &password, unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);

bool encryptFile(const std::filesystem::path &inputPath, const std::filesystem::path &outputPath, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);

bool decryptFile(const std::filesystem::path &inputPath, const std::filesystem::path &outputPath, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);

#endif
