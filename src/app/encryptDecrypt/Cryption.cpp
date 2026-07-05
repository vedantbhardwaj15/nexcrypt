#include "Cryption.hpp"

#include <sodium.h>

#include <array>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace
{
    constexpr std::array<char, 9> MAGIC = {'N', 'E', 'X', 'C', 'R', 'Y', 'P', 'T', '1'};
    constexpr std::size_t PLAIN_CHUNK_SIZE = 64 * 1024;
    constexpr std::size_t CIPHER_CHUNK_SIZE = PLAIN_CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES;

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
    return sodium_init() >= 0;
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

    std::ofstream out(outputPath, std::ios::binary | std::ios::trunc);
    if (!out.is_open())
    {
        std::cerr << "Unable to open output file: " << outputPath << std::endl;
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
        sodium_memzero(key, sizeof key);
        return false;
    }

    crypto_secretstream_xchacha20poly1305_init_push(&state, header, key); // actual encryption of the stream starts.

    if (!writeChars(out, MAGIC.data(), MAGIC.size()) ||
        !writeBytes(out, salt, sizeof salt) ||
        !writeBytes(out, header, sizeof header))
    {
        std::cerr << "Failed to write encrypted file header" << std::endl;
        sodium_memzero(key, sizeof key);
        sodium_memzero(&state, sizeof state);
        return false;
    }

    std::vector<unsigned char> plain(PLAIN_CHUNK_SIZE);
    std::vector<unsigned char> cipher(CIPHER_CHUNK_SIZE);

    while (true)
    {
        // reinterpret_cast is used to point to memory of a diff type so it changes the pointer type. static_cast is used to convert one type to another

        /*
        Read upto the 64 kb of the file into plain buffer. 
        The read function returns the number of bytes read, which is stored in bytesRead. 
        If the end of the file is reached, the eof() function will return true, and the loop will exit.
        */
        in.read(reinterpret_cast<char *>(plain.data()), static_cast<std::streamsize>(plain.size())); 

        const std::streamsize bytesRead = in.gcount(); //This tells how many bytes were actually read from the file. It is important to check this value because the last chunk of data read from the file may be smaller than the buffer size, especially if the file size is not a multiple of the buffer size.

        /*  in.fail() alone   → could mean EOF (expected) OR a real error (unexpected)
            !in.eof() && in.fail()  -> fail happened, AND it's NOT because of EOF, so it must be a REAL error (disk issue, corrupted file, etc.)
        */
        if (bytesRead < 0 || (!in.eof() && in.fail()))
        {
            std::cerr << "Failed while reading input file" << std::endl;
            sodium_memzero(key, sizeof key);
            sodium_memzero(&state, sizeof state);
            return false;
        }

        const bool finalChunk = in.eof();
        unsigned long long cipherLength = 0;
        crypto_secretstream_xchacha20poly1305_push(
            &state,
            cipher.data(),
            &cipherLength,
            plain.data(),
            static_cast<unsigned long long>(bytesRead),// The length of the plaintext data to be encrypted.
            nullptr,
            0,
            finalChunk ? crypto_secretstream_xchacha20poly1305_TAG_FINAL // end of encryption stream
            : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE); // more chunks are comming 

        if (!writeBytes(out, cipher.data(), static_cast<std::size_t>(cipherLength)))
        {
            std::cerr << "Failed while writing encrypted file" << std::endl;
            sodium_memzero(key, sizeof key);
            sodium_memzero(&state, sizeof state);
            return false;
        }

        if (finalChunk)
        {
            break;
        }
    }

    sodium_memzero(key, sizeof key);
    sodium_memzero(&state, sizeof state);
    return true;
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

    std::ofstream out(outputPath, std::ios::binary | std::ios::trunc);
    if (!out.is_open())
    {
        std::cerr << "Unable to open output file: " << outputPath << std::endl;
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
        return false;
    }

    if (!deriveKey(password, salt, key))
    {
        std::cerr << "Failed to derive decryption key" << std::endl;
        sodium_memzero(key, sizeof key);
        return false;
    }

    if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header, key) != 0)
    {
        std::cerr << "Failed to initialize decryption stream" << std::endl;
        sodium_memzero(key, sizeof key);
        return false;
    }

    std::vector<unsigned char> cipher(CIPHER_CHUNK_SIZE);
    std::vector<unsigned char> plain(PLAIN_CHUNK_SIZE);
    bool sawFinal = false;

    while (!sawFinal)
    {
        in.read(reinterpret_cast<char *>(cipher.data()),
                static_cast<std::streamsize>(cipher.size()));
        const std::streamsize bytesRead = in.gcount();

        if (bytesRead == 0)
        {
            std::cerr << "Encrypted file ended before final chunk" << std::endl;
            sodium_memzero(key, sizeof key);
            sodium_memzero(&state, sizeof state);
            return false;
        }

        if (bytesRead < static_cast<std::streamsize>(crypto_secretstream_xchacha20poly1305_ABYTES) ||
            (!in.eof() && in.fail()))
        {
            std::cerr << "Invalid encrypted chunk" << std::endl;
            sodium_memzero(key, sizeof key);
            sodium_memzero(&state, sizeof state);
            return false;
        }

        unsigned long long plainLength = 0;
        unsigned char tag = 0;
        if (crypto_secretstream_xchacha20poly1305_pull(
                &state,
                plain.data(), &plainLength,  // OUTPUT: decrypted bytes go here
                &tag,                        // OUTPUT: what kind of chunk was this?
                cipher.data(),               // INPUT: encrypted bytes read from file
                static_cast<unsigned long long>(bytesRead),
                nullptr,
                0) != 0)
        {
            std::cerr << "Decryption failed. Wrong password or corrupted file." << std::endl;
            sodium_memzero(key, sizeof key);
            sodium_memzero(&state, sizeof state);
            return false;
        }

        if (!writeBytes(out, plain.data(), static_cast<std::size_t>(plainLength)))
        {
            std::cerr << "Failed while writing decrypted file" << std::endl;
            sodium_memzero(key, sizeof key);
            sodium_memzero(&state, sizeof state);
            return false;
        }

        sawFinal = tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL;
        if (sawFinal && in.peek() != std::char_traits<char>::eof())
        {
            std::cerr << "Encrypted file contains extra data after final chunk" << std::endl;
            sodium_memzero(key, sizeof key);
            sodium_memzero(&state, sizeof state);
            return false;
        }
    }

    sodium_memzero(key, sizeof key);
    sodium_memzero(&state, sizeof state);
    return true;
}
