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

    // Header Magic: 9-byte identifier for NEXCRYPT v2 (v3.0.0+) format
    constexpr std::array<char, 9> MAGIC = {'N', 'E', 'X', 'C', 'R', 'Y', 'P', 'T', '2'};

    // Legacy Header Magic: NEXCRYPT1 identifier used in v1.x - v2.0.2 releases
    constexpr std::array<char, 9> LEGACY_MAGIC_V1 = {'N', 'E', 'X', 'C', 'R', 'Y', 'P', 'T', '1'};

    // Per-file salt length (16 bytes = 128-bit entropy for BLAKE2b subkey derivation)
    constexpr std::size_t FILE_SALT_BYTES = 16;

    // Read/write buffer sizing: 256KB plaintext chunks balance I/O efficiency and RAM usage
    constexpr std::size_t PLAIN_CHUNK_SIZE = 256 * 1024;
    constexpr std::size_t CIPHER_CHUNK_SIZE = PLAIN_CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES;

    // Master salt for deriving the session master key from user password via Argon2id
    constexpr unsigned char MASTER_SALT[crypto_pwhash_SALTBYTES] = {
        0x4e, 0x65, 0x78, 0x43, 0x72, 0x79, 0x70, 0x74,
        0x53, 0x61, 0x6c, 0x74, 0x32, 0x30, 0x32, 0x36
    };

    std::once_flag g_cryptoOnceFlag;
    bool cryptoReady = false;

    // Helper: raw binary write to output file stream
    bool writeBytes(std::ofstream &out, const unsigned char *data, std::size_t size)
    {
        out.write(reinterpret_cast<const char *>(data), static_cast<std::streamsize>(size));
        return out.good();
    }

    // Helper: string/char header write to output stream
    bool writeChars(std::ofstream &out, const char *data, std::size_t size)
    {
        out.write(data, static_cast<std::streamsize>(size));
        return out.good();
    }

    // Helper: raw binary read from input file stream
    bool readBytes(std::ifstream &in, unsigned char *data, std::size_t size)
    {
        in.read(reinterpret_cast<char *>(data), static_cast<std::streamsize>(size));
        return in.good();
    }

    // Atomic file replacement: rename temp file to target path once processing completes cleanly.
    // If anything failed, discard the temp file so we never leave partial/corrupted files.
    bool finalizeOutputFile(const fs::path &tempPath, const fs::path &outputPath)
    {
        std::error_code ec;
        fs::remove(outputPath, ec);
        fs::rename(tempPath, outputPath, ec);
        if (ec)
        {
            std::cerr << "[Error] Failed to finalize output file target '" << outputPath.string() 
                      << "': " << ec.message() << '\n';
            fs::remove(tempPath, ec);
            return false;
        }

        return true;
    }

    // Derive a unique 256-bit per-file key using BLAKE2b subkey derivation (crypto_generichash).
    // Uses domain separation context "nexcrypt-file-key" + per-file 16-byte random salt.
    bool deriveFileKey(const unsigned char masterKey[crypto_secretstream_xchacha20poly1305_KEYBYTES],
                       const unsigned char fileSalt[FILE_SALT_BYTES],
                       unsigned char fileKey[crypto_secretstream_xchacha20poly1305_KEYBYTES])
    {
        constexpr char CONTEXT[] = "nexcrypt-file-key";
        crypto_generichash_state st;
        if (crypto_generichash_init(&st, masterKey, crypto_secretstream_xchacha20poly1305_KEYBYTES, crypto_secretstream_xchacha20poly1305_KEYBYTES) != 0)
        {
            return false;
        }
        crypto_generichash_update(&st, reinterpret_cast<const unsigned char *>(CONTEXT), sizeof(CONTEXT) - 1);
        crypto_generichash_update(&st, fileSalt, FILE_SALT_BYTES);
        return crypto_generichash_final(&st, fileKey, crypto_secretstream_xchacha20poly1305_KEYBYTES) == 0;
    }
}

// Thread-safe initialization for libsodium (called once via std::call_once)
bool initializeCrypto()
{
    std::call_once(g_cryptoOnceFlag, []() {
        cryptoReady = sodium_init() >= 0;
    });

    return cryptoReady;
}

// Derive master key ONCE from user password using Argon2id.
bool deriveKeyFromPassword(const std::string &password, unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    if (!initializeCrypto())
    {
        std::cerr << "[Crypto Error] Core cryptographic library (libsodium) initialization failed." << '\n';
        return false;
    }

    if (crypto_pwhash(key,
                      crypto_secretstream_xchacha20poly1305_KEYBYTES,
                      password.c_str(),
                      password.size(),
                      MASTER_SALT,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0)
    {
        std::cerr << "[Crypto Error] Argon2id key derivation (crypto_pwhash) failed." << '\n';
        return false;
    }

    return true;
}

// Encrypt a single file using XChaCha20-Poly1305 chunked secretstream
bool encryptFile(const fs::path &inputPath, const fs::path &outputPath, const unsigned char masterKey[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    if (!initializeCrypto())
    {
        std::cerr << "[Crypto Error] Failed to initialize libsodium for file: " << inputPath.string() << '\n';
        return false;
    }

    std::ifstream in(inputPath, std::ios::binary);
    if (!in.is_open())
    {
        std::cerr << "[I/O Error] Cannot open source file for reading: " << inputPath.string() 
                  << " (check file existence or read permissions)" << '\n';
        return false;
    }

    const fs::path tempOutputPath = fs::path(outputPath.native() + fs::path(".tmp").native());
    std::error_code ec;
    fs::remove(tempOutputPath, ec);

    std::ofstream out(tempOutputPath, std::ios::binary | std::ios::trunc);
    if (!out.is_open())
    {
        std::cerr << "[I/O Error] Cannot create temporary file for writing: " << tempOutputPath.string() 
                  << " (check directory write permissions or disk space)" << '\n';
        return false;
    }

    // 1. Generate a random 16-byte salt for this specific file
    unsigned char fileSalt[FILE_SALT_BYTES];
    randombytes_buf(fileSalt, sizeof fileSalt);

    // 2. Derive unique per-file key from master key using BLAKE2b
    unsigned char fileKey[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    if (!deriveFileKey(masterKey, fileSalt, fileKey))
    {
        std::cerr << "[Crypto Error] BLAKE2b subkey derivation failed for file: " << inputPath.string() << '\n';
        out.close();
        fs::remove(tempOutputPath, ec);
        return false;
    }

    // 3. Initialize secretstream with the derived per-file key
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state state;

    if (crypto_secretstream_xchacha20poly1305_init_push(&state, header, fileKey) != 0)
    {
        sodium_memzero(fileKey, sizeof fileKey);
        std::cerr << "[Crypto Error] XChaCha20-Poly1305 stream push initialization failed." << '\n';
        out.close();
        fs::remove(tempOutputPath, ec);
        return false;
    }

    // 4. Write header layout: [ MAGIC (9B) ] [ FILE_SALT (16B) ] [ STREAM_HEADER (24B) ]
    if (!writeChars(out, MAGIC.data(), MAGIC.size()) ||
        !writeBytes(out, fileSalt, sizeof fileSalt) ||
        !writeBytes(out, header, sizeof header))
    {
        sodium_memzero(fileKey, sizeof fileKey);
        std::cerr << "[I/O Error] Failed to write NEXCRYPT2 header to destination file: " << tempOutputPath.string() << '\n';
        out.close();
        fs::remove(tempOutputPath, ec);
        return false;
    }

    std::vector<unsigned char> plain(PLAIN_CHUNK_SIZE);
    std::vector<unsigned char> cipher(CIPHER_CHUNK_SIZE);

    // 5. Encrypt stream in 256KB chunks
    bool success = true;
    while (success)
    {
        in.read(reinterpret_cast<char *>(plain.data()), static_cast<std::streamsize>(plain.size()));
        const std::streamsize bytesRead = in.gcount();

        if (bytesRead < 0 || (!in.eof() && in.fail()))
        {
            std::cerr << "[I/O Error] Failed reading input data stream from: " << inputPath.string() << '\n';
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
            std::cerr << "[Crypto Error] XChaCha20-Poly1305 chunk encryption failed." << '\n';
            success = false;
            break;
        }

        if (!writeBytes(out, cipher.data(), static_cast<std::size_t>(cipherLength)))
        {
            std::cerr << "[I/O Error] Failed writing encrypted chunk to disk (disk full or write error)." << '\n';
            success = false;
            break;
        }

        if (finalChunk)
        {
            break;
        }
    }

    // Wipe per-file key from memory as soon as encryption finishes
    sodium_memzero(fileKey, sizeof fileKey);
    out.close();

    if (!success)
    {
        fs::remove(tempOutputPath, ec);
        return false;
    }

    return finalizeOutputFile(tempOutputPath, outputPath);
}

// Decrypt a single file and verify authenticated tag chunks
bool decryptFile(const fs::path &inputPath, const fs::path &outputPath, const unsigned char masterKey[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    if (!initializeCrypto())
    {
        std::cerr << "[Crypto Error] Failed to initialize libsodium for decryption." << '\n';
        return false;
    }

    std::ifstream in(inputPath, std::ios::binary);
    if (!in.is_open())
    {
        std::cerr << "[I/O Error] Cannot open encrypted file for reading: " << inputPath.string() 
                  << " (file missing or permission denied)" << '\n';
        return false;
    }

    const fs::path tempOutputPath = fs::path(outputPath.native() + fs::path(".tmp").native());
    std::error_code ec;
    fs::remove(tempOutputPath, ec);

    std::ofstream out(tempOutputPath, std::ios::binary | std::ios::trunc);
    if (!out.is_open())
    {
        std::cerr << "[I/O Error] Cannot create temporary file for decrypted output: " << tempOutputPath.string() << '\n';
        return false;
    }

    std::array<char, MAGIC.size()> magic{};
    unsigned char fileSalt[FILE_SALT_BYTES];
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state state;

    // 1. Read and verify Magic Header
    in.read(magic.data(), static_cast<std::streamsize>(magic.size()));

    if (!in.good())
    {
        std::cerr << "[Format Error] Unable to read magic header from file: " << inputPath.string() 
                  << " (file size is less than 9 bytes)" << '\n';
        out.close();
        fs::remove(tempOutputPath, ec);
        return false;
    }

    if (magic == LEGACY_MAGIC_V1)
    {
        std::cerr << "[Format Error] File '" << inputPath.filename().string() 
                  << "' uses legacy format NEXCRYPT1 (v2.0.2 or older). NEXCRYPT1 files are unsupported in v3.0.0+." << '\n';
        out.close();
        fs::remove(tempOutputPath, ec);
        return false;
    }

    if (magic != MAGIC)
    {
        std::cerr << "[Format Error] Invalid magic identifier in '" << inputPath.filename().string() 
                  << "'. Expected 'NEXCRYPT2' header." << '\n';
        out.close();
        fs::remove(tempOutputPath, ec);
        return false;
    }

    // 2. Read per-file salt and secretstream header
    if (!readBytes(in, fileSalt, sizeof fileSalt) ||
        !readBytes(in, header, sizeof header))
    {
        std::cerr << "[Format Error] Header truncated in '" << inputPath.filename().string() 
                  << "' (file damaged or incomplete, expected 49-byte header)." << '\n';
        out.close();
        fs::remove(tempOutputPath, ec);
        return false;
    }

    // 3. Re-derive per-file key using Master Key and file salt
    unsigned char fileKey[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    if (!deriveFileKey(masterKey, fileSalt, fileKey))
    {
        std::cerr << "[Crypto Error] Failed to derive per-file key for: " << inputPath.string() << '\n';
        out.close();
        fs::remove(tempOutputPath, ec);
        return false;
    }

    // 4. Initialize decryption secretstream
    if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header, fileKey) != 0)
    {
        sodium_memzero(fileKey, sizeof fileKey);
        std::cerr << "[Crypto Error] XChaCha20-Poly1305 pull initialization failed for: " << inputPath.string() << '\n';
        out.close();
        fs::remove(tempOutputPath, ec);
        return false;
    }

    std::vector<unsigned char> cipher(CIPHER_CHUNK_SIZE);
    std::vector<unsigned char> plain(PLAIN_CHUNK_SIZE);
    bool sawFinal = false;
    bool success = true;

    // 5. Decrypt chunk by chunk
    while (!sawFinal && success)
    {
        in.read(reinterpret_cast<char *>(cipher.data()),
                static_cast<std::streamsize>(cipher.size()));
        const std::streamsize bytesRead = in.gcount();

        if (bytesRead == 0)
        {
            std::cerr << "[Corrupt File Error] Encrypted file ended unexpectedly before final block was read: " 
                      << inputPath.filename().string() << '\n';
            success = false;
            break;
        }

        if (bytesRead < static_cast<std::streamsize>(crypto_secretstream_xchacha20poly1305_ABYTES) ||
            (!in.eof() && in.fail()))
        {
            std::cerr << "[Format Error] Invalid encrypted chunk size in: " << inputPath.filename().string() << '\n';
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
            std::cerr << "[Auth Error] Decryption/Authentication failed for: " << inputPath.filename().string() 
                      << " (incorrect password or corrupted/tampered ciphertext)." << '\n';
            success = false;
            break;
        }

        if (!writeBytes(out, plain.data(), static_cast<std::size_t>(plainLength)))
        {
            std::cerr << "[I/O Error] Failed writing decrypted plaintext to disk." << '\n';
            success = false;
            break;
        }

        sawFinal = tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL;
        if (sawFinal && in.peek() != std::char_traits<char>::eof())
        {
            std::cerr << "[Format Error] Trailing extra data detected after final chunk in: " 
                      << inputPath.filename().string() << '\n';
            success = false;
            break;
        }
    }

    // Clean up per-file key buffer immediately after decryption
    sodium_memzero(fileKey, sizeof fileKey);
    out.close();

    if (!success)
    {
        fs::remove(tempOutputPath, ec);
        return false;
    }

    return finalizeOutputFile(tempOutputPath, outputPath);
}
