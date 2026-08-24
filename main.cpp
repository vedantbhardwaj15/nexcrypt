#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>

// Cross-platform console includes for password masking and ANSI setup
#if defined(_WIN32)
#include <windows.h>
#elif defined(__unix__)
#include <termios.h>
#include <unistd.h>
#endif

#include "./src/app/common/Colors.hpp"
#include "./src/app/processes/ProcessManagement.hpp"

namespace fs = std::filesystem;

namespace {

/**
 * Converts a string to uppercase (used for case-insensitive action comparison).
 */
std::string toUpper(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::toupper(ch));
    });
    return value;
}

/**
 * Trims surrounding whitespace and quotation marks (e.g. from file drag-and-drop).
 */
std::string trimWhitespaceAndQuotes(std::string str) {
    std::size_t start = 0;
    while (start < str.size() && (std::isspace(static_cast<unsigned char>(str[start])) || str[start] == '\"' || str[start] == '\'')) {
        start++;
    }
    std::size_t end = str.size();
    while (end > start && (std::isspace(static_cast<unsigned char>(str[end - 1])) || str[end - 1] == '\"' || str[end - 1] == '\'')) {
        end--;
    }
    return str.substr(start, end - start);
}

/**
 * Checks if a file path has the ".nex" extension.
 */
bool hasNexExtension(const fs::path &path) {
    return path.extension() == ".nex";
}

/**
 * Validates whether a file should be processed:
 * - When ENCRYPTING: skips files that are already encrypted (*.nex)
 * - When DECRYPTING: skips files that do not have the *.nex extension
 */
bool shouldProcessFile(const fs::path &filePath, const std::string &action) {
    if (action == "ENCRYPT") {
        if (hasNexExtension(filePath)) {
            std::cout << Color::Yellow << "[!] Skipping already encrypted file: " << Color::Reset << safePathString(filePath) << '\n';
            return false;
        }
        return true;
    }

    if (!hasNexExtension(filePath)) {
        std::cout << Color::Yellow << "[!] Skipping non-.nex file: " << Color::Reset << safePathString(filePath) << '\n';
        return false;
    }
    return true;
}

/**
 * Securely overwrites the password buffer with zeroes in memory.
 */
void scrubPassword(std::string &password) {
    std::fill(password.begin(), password.end(), '\0');
    password.clear();
}

/**
 * Formats a raw byte count into human-readable units (GB, MB, KB).
 */
std::string formatBytes(std::uint64_t bytes) {
    char buf[32];
    if (bytes >= (std::uint64_t)1024 * 1024 * 1024)
        std::snprintf(buf, sizeof(buf), "%.2f GB", static_cast<double>(bytes) / (1024.0 * 1024 * 1024));
    else if (bytes >= (std::uint64_t)1024 * 1024)
        std::snprintf(buf, sizeof(buf), "%.2f MB", static_cast<double>(bytes) / (1024.0 * 1024));
    else
        std::snprintf(buf, sizeof(buf), "%.2f KB", static_cast<double>(bytes) / 1024.0);
    return buf;
}

/**
 * Reads a password from standard input with terminal echo disabled (masked input).
 * Compatible with both POSIX (termios) and Windows (SetConsoleMode).
 */
bool readPasswordMasked(std::string &password) {
    password.clear();
    password.reserve(256);

#if defined(_WIN32)
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD oldMode = 0;
    const bool hasConsole = (hStdin != INVALID_HANDLE_VALUE && GetConsoleMode(hStdin, &oldMode));
    if (hasConsole) {
        SetConsoleMode(hStdin, oldMode & ~ENABLE_ECHO_INPUT);
    }
#elif defined(__unix__)
    termios oldTerm{};
    const bool hasTerm = (tcgetattr(STDIN_FILENO, &oldTerm) == 0);
    if (hasTerm) {
        termios newTerm = oldTerm;
        newTerm.c_lflag &= static_cast<unsigned int>(~ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &newTerm);
    }
#endif

    std::cout << "Enter password:" << std::endl;
    std::getline(std::cin, password);

#if defined(_WIN32)
    if (hasConsole) {
        SetConsoleMode(hStdin, oldMode);
    }
#elif defined(__unix__)
    if (hasTerm) {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldTerm);
    }
#endif
    std::cout << std::endl;
    return true;
}

} // anonymous namespace

int main() {
    // Enable UTF-8 and ANSI Virtual Terminal Processing on Windows systems
#if defined(_WIN32)
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    if (hOut != INVALID_HANDLE_VALUE && GetConsoleMode(hOut, &dwMode)) {
        SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
#endif

    // ======================================================================
    // STEP 1: Gather User Inputs via Interactive CLI
    // ======================================================================
    
    std::string pathInput;
    std::string action;
    std::string password;

    std::cout << "Enter file or directory path:" << std::endl;
    std::getline(std::cin, pathInput);
    pathInput = trimWhitespaceAndQuotes(pathInput);

    std::cout << "Enter action (ENCRYPT/DECRYPT):" << std::endl;
    std::getline(std::cin, action);
    action = toUpper(trimWhitespaceAndQuotes(action));

    if (action != "ENCRYPT" && action != "DECRYPT") {
        std::cerr << Color::BoldRed << "Error: " << Color::Reset << "Invalid action. Must be ENCRYPT or DECRYPT." << std::endl;
        return 1;
    }

    if (!readPasswordMasked(password) || password.empty()) {
        scrubPassword(password);
        std::cerr << Color::BoldRed << "Error: " << Color::Reset << "Password cannot be empty." << std::endl;
        return 1;
    }

    bool preserveOriginals = true;
    if (action == "ENCRYPT") {
        std::cout << "Delete original files after encryption? (y/N): ";
        std::string choice;
        std::getline(std::cin, choice);
        choice = trimWhitespaceAndQuotes(choice);
        if (!choice.empty() && (choice[0] == 'y' || choice[0] == 'Y')) {
            preserveOriginals = false;
        }
    }

    // Configure thread pool concurrency
    int numWorkers = 4;
    std::cout << "Enter number of parallel workers (default 4): ";
    std::string workerInput;
    std::getline(std::cin, workerInput);
    try {
        if (!workerInput.empty()) {
            numWorkers = std::stoi(workerInput);
        }
    } catch (...) {
        numWorkers = 4;
    }

    // Configure streaming chunk size (in KB; must be within [4 KB, 16384 KB] bounds)
    std::size_t chunkSizeKB = 256;
    if (action == "ENCRYPT") {
        std::cout << "Enter chunk size in KB (default 256, min 4, max 16384): ";
        std::string chunkInput;
        std::getline(std::cin, chunkInput);
        try {
            if (!chunkInput.empty()) {
                std::size_t parsed = std::stoull(chunkInput);
                if (parsed < 4 || parsed > 16384) {
                    std::cerr << Color::BoldYellow << "Warning: " << Color::Reset << "Chunk size must be between 4 KB and 16384 KB (16 MB). Using default 256 KB.\n";
                    chunkSizeKB = 256;
                } else {
                    chunkSizeKB = parsed;
                }
            }
        } catch (...) {
            chunkSizeKB = 256;
        }
    }

    const fs::path target(pathInput);

    // ======================================================================
    // STEP 2: File Discovery & Task Queue Population
    // ======================================================================
    try {
        ProcessManagement pm(numWorkers, chunkSizeKB);
        int fileCount = 0;
        std::uint64_t totalSizeForDisplay = 0;
        const Action taskAction = (action == "ENCRYPT") ? Action::ENCRYPT : Action::DECRYPT;

        std::error_code isRegEc;
        if (fs::is_regular_file(target, isRegEc)) {
            // Target is a single file
            if (shouldProcessFile(target, action)) {
                std::error_code szEc;
                const auto rawSize = fs::file_size(target, szEc);
                const std::uint64_t fsz = szEc ? 0 : static_cast<std::uint64_t>(rawSize);
                totalSizeForDisplay = fsz;
                pm.submitToQueue(std::make_unique<Task>(taskAction, target, fsz));
                fileCount++;
            }
        } else {
            // Target is a directory: recursively discover all regular files
            std::error_code isDirEc;
            if (fs::is_directory(target, isDirEc)) {
                std::cout << Color::Dim << "Scanning directory...\n" << Color::Reset;
                std::error_code ec;
                fs::recursive_directory_iterator it(target, fs::directory_options::skip_permission_denied, ec);
                fs::recursive_directory_iterator end;

                for (; it != end; it.increment(ec)) {
                    if (ec) {
                        std::cerr << Color::BoldYellow << "Warning: " << Color::Reset << "could not access a directory entry: " << ec.message() << '\n';
                        ec.clear();
                        continue;
                    }

                    try {
                        std::error_code entryEc;
                        const fs::directory_entry &entry = *it;
                        if (!entry.is_regular_file(entryEc)) {
                            continue;
                        }

                        if (!shouldProcessFile(entry.path(), action)) {
                            continue;
                        }

                        std::error_code szEc;
                        const auto rawSize = entry.file_size(szEc);
                        const std::uint64_t fsz = szEc ? 0 : static_cast<std::uint64_t>(rawSize);
                        totalSizeForDisplay += fsz;
                        pm.submitToQueue(std::make_unique<Task>(taskAction, entry.path(), fsz));
                        fileCount++;
                    } catch (const std::exception &ex) {
                        std::cerr << Color::BoldYellow << "Warning: " << Color::Reset << "skipping problematic file: " << ex.what() << '\n';
                    } catch (...) {
                        std::cerr << Color::BoldYellow << "Warning: " << Color::Reset << "skipping problematic file.\n";
                    }
                }
            } else {
                std::cerr << Color::BoldRed << "Error: " << Color::Reset << "Path does not exist or is not a regular file/directory." << std::endl;
                scrubPassword(password);
                return 1;
            }
        }

        // Exit early if no eligible files were queued
        if (fileCount == 0) {
            std::cout << Color::Yellow << "No files to process.\n" << Color::Reset;
            scrubPassword(password);
            return 0;
        }

        std::cout << Color::BoldGreen << "[+] " << Color::Reset << "Found: " << Color::Bold << fileCount << Color::Reset << (fileCount == 1 ? " file (" : " files (")
                  << Color::Bold << formatBytes(totalSizeForDisplay) << Color::Reset << ")\n\n";

        const char *verb = (action == "ENCRYPT") ? "Encrypting" : "Decrypting";
        std::cout << Color::Cyan << verb << "...\n\n" << Color::Reset;
        
        // ==================================================================
        // STEP 3: Multi-Threaded Task Execution
        // ==================================================================

        // Spawn workers, start progress bar, process tasks, and show summary
        const bool success = pm.executeTasks(password, preserveOriginals);

        // Wipe password from memory before terminating
        scrubPassword(password);
        return success ? 0 : 1;

    } catch (const fs::filesystem_error &ex) {
        std::cerr << Color::BoldRed << "Filesystem error: " << Color::Reset << ex.what() << std::endl;
        scrubPassword(password);
        return 1;
    } catch (const std::exception &ex) {
        std::cerr << Color::BoldRed << "Error: " << Color::Reset << ex.what() << std::endl;
        scrubPassword(password);
        return 1;
    }
}
