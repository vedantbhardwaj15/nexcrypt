#include "Cryption.hpp"

#include <sodium.h>

#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <vector>

namespace
{
    namespace fs = std::filesystem;

    constexpr std::array<char, 9> MAGIC = {'N', 'E', 'X', 'C', 'R', 'Y', 'P', 'T', '1'};
    constexpr std::size_t PLAIN_CHUNK_SIZE = 256 * 1024;
    constexpr std::size_t CIPHER_CHUNK_SIZE = PLAIN_CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES;

    std::once_flag g_cryptoOnceFlag;
    bool cryptoReady = false;

    bool writeBytes(std::ofstream &out, const unsigned char *data, std::size_t size)
    {
        out.write(reinterpret_cast<const char *>(data), static_cast<std::streamsize>(size));
        return out.good();
    }

    bool writeChars(std::ofstream &out, const char *data, std::size_t size)
    {
        out.write(data, static_cast<std::streamsize>(size));
        return out.good();
    }

    bool readBytes(std::ifstream &in, unsigned char *data, std::size_t size)
    {
        in.read(reinterpret_cast<char *>(data), static_cast<std::streamsize>(size));
        return in.good();
    }

    // Derive key from password + salt.
    bool deriveKey(const std::string &password,
                   const unsigned char salt[crypto_pwhash_SALTBYTES],
                   unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
    {
        return crypto_pwhash(key,
                             crypto_secretstream_xchacha20poly1305_KEYBYTES,
                             password.c_str(),
                             password.size(),
                             salt,
                             crypto_pwhash_OPSLIMIT_INTERACTIVE,
                             crypto_pwhash_MEMLIMIT_INTERACTIVE,
                             crypto_pwhash_ALG_DEFAULT) == 0;
    }

    bool finalizeOutputFile(const fs::path &tempPath, const fs::path &outputPath)
    {
        std::error_code ec;
        fs::remove(outputPath, ec);
        fs::rename(tempPath, outputPath, ec);
        if (ec)
        {
            std::cerr << "Failed to finalize output file: " << ec.message() << std::endl;
            fs::remove(tempPath, ec);
            return false;
        }

        return true;
    }
}
/* sodium_init is a function of libsodium library that inititalizes it before performing any of its cryptographic functions
-> Initializing internal cryptographic components.
-> Setting up secure random number generation.
-> Performing platform-specific initialization.
-> Ensuring the library is ready for cryptographic operations.
*/
/*
0 → initialization succeeded.
1 → library was already initialized.
-1 → initialization failed.
*/
bool initializeCrypto()
{
    std::call_once(g_cryptoOnceFlag, []() {
        cryptoReady = sodium_init() >= 0;
    });

    return cryptoReady;
}

bool encryptFile(const std::string &inputPath, const std::string &outputPath, const std::string &password)
{
    if (!initializeCrypto())
    {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return false;
    }

    std::ifstream in(inputPath, std::ios::binary);
    if (!in.is_open())
    {
        std::cerr << "Unable to open input file: " << inputPath << std::endl;
        return false;
    }

    const fs::path tempOutputPath = fs::path(outputPath + ".tmp");
    std::error_code ec;
    fs::remove(tempOutputPath, ec);

    std::ofstream out(tempOutputPath, std::ios::binary | std::ios::trunc);
    if (!out.is_open())
    {
        std::cerr << "Unable to open temporary output file: " << tempOutputPath << std::endl;
        return false;
    }

    unsigned char salt[crypto_pwhash_SALTBYTES];                             // 16 bytes
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];       // 32 bytes
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES]; // 24 bytes

    // info needed to decrypt the stream later. The header is not secret, but it must be saved or transmitted with the ciphertext.

    crypto_secretstream_xchacha20poly1305_state state; // Keeps track of stream encryption as data is processed in chunks. It maintains the internal state of the encryption process, including the key, nonce, and any other necessary information to ensure that each chunk is encrypted correctly and securely.

    randombytes_buf(salt, sizeof salt); // generates random salt to fill the salt buffer with random bytes.

    if (!deriveKey(password, salt, key))
    {
        std::cerr << "Failed to derive encryption key" << std::endl;
        out.close();
        fs::remove(tempOutputPath, ec);
        sodium_memzero(key, sizeof key);
        return false;
    }

    const int initPushResult = crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);
    if (initPushResult != 0)
    {
        std::cerr << "Failed to initialize encryption stream" << std::endl;
        out.close();
        fs::remove(tempOutputPath, ec);
        sodium_memzero(key, sizeof key);
        sodium_memzero(&state, sizeof state);
        return false;
    }

    if (!writeChars(out, MAGIC.data(), MAGIC.size()) ||
        !writeBytes(out, salt, sizeof salt) ||
        !writeBytes(out, header, sizeof header))
    {
        std::cerr << "Failed to write encrypted file header" << std::endl;
        out.close();
        fs::remove(tempOutputPath, ec);
        sodium_memzero(key, sizeof key);
        sodium_memzero(&state, sizeof state);
        return false;
    }

    std::vector<unsigned char> plain(PLAIN_CHUNK_SIZE);
    std::vector<unsigned char> cipher(CIPHER_CHUNK_SIZE);

    bool success = true;
    while (success)
    {
        // reinterpret_cast is used to point to memory of a diff type so it changes the pointer type. static_cast is used to convert one type to another

        /*
        Read upto the 256 kb of the file into plain buffer. 
        The read function returns the number of bytes read, which is stored in bytesRead. 
        If the end of the file is reached, the eof() function will return true, and the loop will exit.
        */
        in.read(reinterpret_cast<char *>(plain.data()), static_cast<std::streamsize>(plain.size()));
        const std::streamsize bytesRead = in.gcount(); 

        /*  in.fail() alone   → could mean EOF (expected) OR a real error (unexpected)
            !in.eof() && in.fail()  -> fail happened, AND it's NOT because of EOF, so it must be a REAL error (disk issue, corrupted file, etc.)
        */
        if (bytesRead < 0 || (!in.eof() && in.fail()))
        {
            std::cerr << "Failed while reading input file" << std::endl;
            success = false;
            break;
        }

        const bool finalChunk = in.eof();
        unsigned long long cipherLength = 0;
        const int pushResult = crypto_secretstream_xchacha20poly1305_push(
            &state,
            cipher.data(),
            &cipherLength,
            plain.data(),
            static_cast<unsigned long long>(bytesRead),
            nullptr,
            0,
            finalChunk ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
                      : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);

        if (pushResult != 0)
        {
            std::cerr << "Failed while encrypting stream chunk" << std::endl;
            success = false;
            break;
        }

        if (!writeBytes(out, cipher.data(), static_cast<std::size_t>(cipherLength)))
        {
            std::cerr << "Failed while writing encrypted file" << std::endl;
            success = false;
            break;
        }

        if (finalChunk)
        {
            break;
        }
    }

    out.close();

    if (!success)
    {
        fs::remove(tempOutputPath, ec);
        sodium_memzero(key, sizeof key);
        sodium_memzero(&state, sizeof state);
        sodium_memzero(plain.data(), plain.size());
        sodium_memzero(cipher.data(), cipher.size());
        return false;
    }

    const bool finalized = finalizeOutputFile(tempOutputPath, fs::path(outputPath));

    sodium_memzero(key, sizeof key);
    sodium_memzero(&state, sizeof state);
    sodium_memzero(plain.data(), plain.size());
    sodium_memzero(cipher.data(), cipher.size());
    return finalized;
}

bool decryptFile(const std::string &inputPath, const std::string &outputPath, const std::string &password)
{
    if (!initializeCrypto())
    {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return false;
    }

    std::ifstream in(inputPath, std::ios::binary);
    if (!in.is_open())
    {
        std::cerr << "Unable to open input file: " << inputPath << std::endl;
        return false;
    }

    const fs::path tempOutputPath = fs::path(outputPath + ".tmp");
    std::error_code ec;
    fs::remove(tempOutputPath, ec);

    std::ofstream out(tempOutputPath, std::ios::binary | std::ios::trunc);
    if (!out.is_open())
    {
        std::cerr << "Unable to open temporary output file: " << tempOutputPath << std::endl;
        return false;
    }

    std::array<char, MAGIC.size()> magic{};
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state state;

    in.read(magic.data(), static_cast<std::streamsize>(magic.size()));

    if (!in.good() || magic != MAGIC ||
        !readBytes(in, salt, sizeof salt) ||
        !readBytes(in, header, sizeof header))
    {
        std::cerr << "Invalid or unsupported encrypted file format" << std::endl;
        out.close();
        fs::remove(tempOutputPath, ec);
        return false;
    }

    if (!deriveKey(password, salt, key))
    {
        std::cerr << "Failed to derive decryption key" << std::endl;
        out.close();
        fs::remove(tempOutputPath, ec);
        sodium_memzero(key, sizeof key);
        return false;
    }

    if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header, key) != 0)
    {
        std::cerr << "Failed to initialize decryption stream" << std::endl;
        out.close();
        fs::remove(tempOutputPath, ec);
        sodium_memzero(key, sizeof key);
        return false;
    }

    std::vector<unsigned char> cipher(CIPHER_CHUNK_SIZE);
    std::vector<unsigned char> plain(PLAIN_CHUNK_SIZE);
    bool sawFinal = false;
    bool success = true;

    while (!sawFinal && success)
    {
        in.read(reinterpret_cast<char *>(cipher.data()),
                static_cast<std::streamsize>(cipher.size()));
        const std::streamsize bytesRead = in.gcount();

        if (bytesRead == 0)
        {
            std::cerr << "Encrypted file ended before final chunk" << std::endl;
            success = false;
            break;
        }

        if (bytesRead < static_cast<std::streamsize>(crypto_secretstream_xchacha20poly1305_ABYTES) ||
            (!in.eof() && in.fail()))
        {
            std::cerr << "Invalid encrypted chunk" << std::endl;
            success = false;
            break;
        }

        unsigned long long plainLength = 0;
        unsigned char tag = 0;
        if (crypto_secretstream_xchacha20poly1305_pull(
                &state,
                plain.data(), &plainLength,
                &tag,
                cipher.data(),
                static_cast<unsigned long long>(bytesRead),
                nullptr,
                0) != 0)
        {
            std::cerr << "Decryption failed. Wrong password or corrupted file." << std::endl;
            success = false;
            break;
        }

        if (!writeBytes(out, plain.data(), static_cast<std::size_t>(plainLength)))
        {
            std::cerr << "Failed while writing decrypted file" << std::endl;
            success = false;
            break;
        }

        sawFinal = tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL;
        if (sawFinal && in.peek() != std::char_traits<char>::eof())
        {
            std::cerr << "Encrypted file contains extra data after final chunk" << std::endl;
            success = false;
            break;
        }
    }

    out.close();

    if (!success)
    {
        fs::remove(tempOutputPath, ec);
        sodium_memzero(key, sizeof key);
        sodium_memzero(&state, sizeof state);
        sodium_memzero(plain.data(), plain.size());
        sodium_memzero(cipher.data(), cipher.size());
        return false;
    }

    const bool finalized = finalizeOutputFile(tempOutputPath, fs::path(outputPath));

    sodium_memzero(key, sizeof key);
    sodium_memzero(&state, sizeof state);
    sodium_memzero(plain.data(), plain.size());
    sodium_memzero(cipher.data(), cipher.size());
    return finalized;
}
