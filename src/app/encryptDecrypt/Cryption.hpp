#ifndef CRYPTION_HPP
#define CRYPTION_HPP

#include <filesystem>
#include <string>
#include <vector>
#include <sodium.h>

// Chunk sizing constants (exposed for buffer pre-allocation by worker threads)
constexpr std::size_t NEXCRYPT_PLAIN_CHUNK_SIZE = 256 * 1024;
constexpr std::size_t NEXCRYPT_CIPHER_CHUNK_SIZE = NEXCRYPT_PLAIN_CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES;

bool initializeCrypto();

bool deriveKeyFromPassword(const std::string &password, unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);

bool encryptFile(const std::filesystem::path &inputPath, const std::filesystem::path &outputPath,
                 const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES],
                 std::vector<unsigned char> &plainBuf, std::vector<unsigned char> &cipherBuf);

bool decryptFile(const std::filesystem::path &inputPath, const std::filesystem::path &outputPath,
                 const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES],
                 std::vector<unsigned char> &cipherBuf, std::vector<unsigned char> &plainBuf);

#endif

