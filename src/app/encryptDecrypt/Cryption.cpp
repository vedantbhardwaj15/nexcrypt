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

#ifdef __linux__
#include <fcntl.h>
#include <unistd.h>
#endif

namespace
{
    namespace fs = std::filesystem;

    // Header Magic: 9-byte identifier for NEXCRYPT v2 format
    constexpr std::array<char, 9> MAGIC = {'N', 'E', 'X', 'C', 'R', 'Y', 'P', 'T', '2'};

    // Legacy magic identifiers — kept for clear error messages on old files.
    constexpr std::array<char, 9> LEGACY_MAGIC_V1 = {'N', 'E', 'X', 'C', 'R', 'Y', 'P', 'T', '1'};

    // Per-file salt length (16 bytes = 128-bit entropy for BLAKE2b subkey derivation)
    constexpr std::size_t FILE_SALT_BYTES = 16;

    // Bytes reserved in the header to store the plain chunk size (uint32_t, little-endian).
    constexpr std::size_t CHUNK_SIZE_BYTES = 4;

    // Allowed chunk size boundaries for validation.
    constexpr std::uint32_t MIN_CHUNK = 4 * 1024;          // 4 KB
    constexpr std::uint32_t MAX_CHUNK = 16 * 1024 * 1024;  // 16 MB

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
bool encryptFile(const fs::path &inputPath, const fs::path &outputPath,
                 const unsigned char masterKey[crypto_secretstream_xchacha20poly1305_KEYBYTES],
                 std::vector<unsigned char> &plainBuf, std::vector<unsigned char> &cipherBuf,
                 std::atomic<std::uint64_t> *bytesProcessed)
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

    // 4. Pack the 53-byte header into a single write call.
    // Layout: [ MAGIC (9B) ] [ PLAIN_CHUNK_SIZE (4B, LE uint32_t) ] [ FILE_SALT (16B) ] [ STREAM_HEADER (24B) ]
    constexpr std::size_t FULL_HEADER_SIZE =
        MAGIC.size() + CHUNK_SIZE_BYTES + FILE_SALT_BYTES +
        crypto_secretstream_xchacha20poly1305_HEADERBYTES;
    unsigned char fullHeader[FULL_HEADER_SIZE];

    // Magic.
    std::memcpy(fullHeader, MAGIC.data(), MAGIC.size());

    // Embed plain chunk size as little-endian uint32_t so decryption is always exact.
    const std::uint32_t chunkBytes = static_cast<std::uint32_t>(plainBuf.size());
    fullHeader[MAGIC.size() + 0] = static_cast<unsigned char>( chunkBytes        & 0xFFu);
    fullHeader[MAGIC.size() + 1] = static_cast<unsigned char>((chunkBytes >>  8) & 0xFFu);
    fullHeader[MAGIC.size() + 2] = static_cast<unsigned char>((chunkBytes >> 16) & 0xFFu);
    fullHeader[MAGIC.size() + 3] = static_cast<unsigned char>((chunkBytes >> 24) & 0xFFu);

    // File salt and secretstream header.
    std::memcpy(fullHeader + MAGIC.size() + CHUNK_SIZE_BYTES, fileSalt, FILE_SALT_BYTES);
    std::memcpy(fullHeader + MAGIC.size() + CHUNK_SIZE_BYTES + FILE_SALT_BYTES, header, sizeof header);

    if (!writeBytes(out, fullHeader, sizeof fullHeader))
    {
        sodium_memzero(fileKey, sizeof fileKey);
        std::cerr << "[I/O Error] Failed to write NEXCRYPT2 header to destination file: " << tempOutputPath.string() << '\n';
        out.close();
        fs::remove(tempOutputPath, ec);
        return false;
    }

    // 5. Encrypt stream using caller-provided reusable buffers
    bool success = true;
    while (success)
    {
        in.read(reinterpret_cast<char *>(plainBuf.data()), static_cast<std::streamsize>(plainBuf.size()));
        const std::streamsize bytesRead = in.gcount();

        if (bytesRead < 0 || (!in.eof() && in.fail()))
        {
            std::cerr << "[I/O Error] Failed reading input data stream from: " << inputPath.string() << '\n';
            success = false;
            break;
        }

        if (bytesProcessed && bytesRead > 0)
        {
            bytesProcessed->fetch_add(static_cast<std::uint64_t>(bytesRead), std::memory_order_relaxed);
        }

        const bool finalChunk = in.eof();
        unsigned long long cipherLength = 0;
        const int pushResult = crypto_secretstream_xchacha20poly1305_push(
            &state,
            cipherBuf.data(),
            &cipherLength,
            plainBuf.data(),
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

        if (!writeBytes(out, cipherBuf.data(), static_cast<std::size_t>(cipherLength)))
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
bool decryptFile(const fs::path &inputPath, const fs::path &outputPath,
                 const unsigned char masterKey[crypto_secretstream_xchacha20poly1305_KEYBYTES],
                 std::vector<unsigned char> &cipherBuf, std::vector<unsigned char> &plainBuf,
                 std::atomic<std::uint64_t> *bytesProcessed)
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

    // 1. Read and verify magic.
    in.read(magic.data(), static_cast<std::streamsize>(magic.size()));

    if (!in.good())
    {
        std::cerr << "[Format Error] Unable to read magic header from file: " << inputPath.string()
                  << " (file is too small)" << '\n';
        out.close();
        fs::remove(tempOutputPath, ec);
        return false;
    }

    if (magic == LEGACY_MAGIC_V1)
    {
        std::cerr << "[Format Error] '" << inputPath.filename().string()
                  << "' uses legacy format NEXCRYPT1. Re-encrypt with the current version." << '\n';
        out.close();
        fs::remove(tempOutputPath, ec);
        return false;
    }

    if (magic != MAGIC)
    {
        std::cerr << "[Format Error] Unrecognised magic in '" << inputPath.filename().string()
                  << "'. Expected NEXCRYPT2 header." << '\n';
        out.close();
        fs::remove(tempOutputPath, ec);
        return false;
    }

    // 2. Read the plain chunk size stored at encryption time (4 bytes, LE uint32_t).
    unsigned char chunkSizeLE[CHUNK_SIZE_BYTES];
    if (!readBytes(in, chunkSizeLE, CHUNK_SIZE_BYTES))
    {
        std::cerr << "[Format Error] Header truncated in '" << inputPath.filename().string()
                  << "' (could not read chunk size field)." << '\n';
        out.close();
        fs::remove(tempOutputPath, ec);
        return false;
    }

    const std::uint32_t storedChunkBytes =
        (static_cast<std::uint32_t>(chunkSizeLE[0])      ) |
        (static_cast<std::uint32_t>(chunkSizeLE[1]) <<  8) |
        (static_cast<std::uint32_t>(chunkSizeLE[2]) << 16) |
        (static_cast<std::uint32_t>(chunkSizeLE[3]) << 24);

    if (storedChunkBytes < MIN_CHUNK || storedChunkBytes > MAX_CHUNK)
    {
        std::cerr << "[Format Error] Invalid chunk size in file header.\n";
        out.close();
        fs::remove(tempOutputPath, ec);
        return false;
    }

    // Resize caller-provided buffers to the exact chunk size used at encryption time.
    // Same-size case: vector::resize is a documented no-op — zero cost.
    // Different-size case: one realloc per file; the worker reuses the resized buffer for the rest of the session.
    const std::size_t storedPlainSize  = static_cast<std::size_t>(storedChunkBytes);
    const std::size_t storedCipherSize = storedPlainSize + crypto_secretstream_xchacha20poly1305_ABYTES;
    if (cipherBuf.size() != storedCipherSize) cipherBuf.resize(storedCipherSize);
    if (plainBuf.size()  != storedPlainSize)  plainBuf.resize(storedPlainSize);

    // 3. Read per-file salt (16B) and secretstream header (24B) in a single packed read (40B).
    constexpr std::size_t REMAINING_HEADER_SIZE =
        FILE_SALT_BYTES + crypto_secretstream_xchacha20poly1305_HEADERBYTES;
    unsigned char remainingHeader[REMAINING_HEADER_SIZE];

    if (!readBytes(in, remainingHeader, sizeof remainingHeader))
    {
        std::cerr << "[Format Error] Header truncated in '" << inputPath.filename().string()
                  << "' (expected 53-byte header)." << '\n';
        out.close();
        fs::remove(tempOutputPath, ec);
        return false;
    }

    std::memcpy(fileSalt, remainingHeader, FILE_SALT_BYTES);
    std::memcpy(header, remainingHeader + FILE_SALT_BYTES, sizeof header);

    if (bytesProcessed)
    {
        bytesProcessed->fetch_add(MAGIC.size() + CHUNK_SIZE_BYTES + REMAINING_HEADER_SIZE, std::memory_order_relaxed);
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

    bool sawFinal = false;
    bool success = true;

    // 5. Decrypt chunk by chunk using caller-provided reusable buffers
    while (!sawFinal && success)
    {
        in.read(reinterpret_cast<char *>(cipherBuf.data()),
                static_cast<std::streamsize>(cipherBuf.size()));
        const std::streamsize bytesRead = in.gcount();

        if (bytesRead == 0)
        {
            std::cerr << "[Corrupt File Error] Encrypted file ended unexpectedly before final block was read: " 
                      << inputPath.filename().string() << '\n';
            success = false;
            break;
        }

        if (bytesProcessed && bytesRead > 0)
        {
            bytesProcessed->fetch_add(static_cast<std::uint64_t>(bytesRead), std::memory_order_relaxed);
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
                plainBuf.data(), &plainLength,
                &tag,
                cipherBuf.data(),
                static_cast<unsigned long long>(bytesRead),
                nullptr,
                0) != 0)
        {
            std::cerr << "[Auth Error] Decryption/Authentication failed for: " << inputPath.filename().string() 
                      << " (incorrect password or corrupted/tampered ciphertext)." << '\n';
            success = false;
            break;
        }

        if (!writeBytes(out, plainBuf.data(), static_cast<std::size_t>(plainLength)))
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
