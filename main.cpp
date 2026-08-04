#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__unix__)
#include <termios.h>
#include <unistd.h>
#endif

#include "./src/app/encryptDecrypt/Cryption.hpp"
#include "./src/app/fileHandling/IO.hpp"
#include "./src/app/processes/ProcessManagement.hpp"

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

bool shouldProcessFile(const fs::path &filePath,
                       const std::string &action) {
    if (action == "ENCRYPT") {
        if (hasNexExtension(filePath)) {
            std::cout << "Skipping already encrypted file: " << safePathString(filePath) << std::endl;
            return false;
        }
        return true;
    }

    if (!hasNexExtension(filePath)) {
        std::lock_guard<std::mutex> lock(getApplicationLogMutex());
        std::cout << "Skipping non-.nex file: " << safePathString(filePath) << std::endl;
        return false;
    }
    return true;
}

void scrubPassword(std::string &password) {
    std::fill(password.begin(), password.end(), '\0');
    password.clear();
}

bool readPasswordMasked(std::string &password) {
    password.clear();
    password.reserve(256);

#if defined(_WIN32)
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD oldMode = 0;
    const bool hasConsole = hStdin != INVALID_HANDLE_VALUE && GetConsoleMode(hStdin, &oldMode);
    if (hasConsole) {
        SetConsoleMode(hStdin, oldMode & ~ENABLE_ECHO_INPUT);
    }
#elif defined(__unix__)
    termios oldTerm{};
    const bool hasTerm = tcgetattr(STDIN_FILENO, &oldTerm) == 0;
    if (hasTerm) {
        termios newTerm = oldTerm;
        newTerm.c_lflag &= static_cast<unsigned int>(~ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &newTerm);
    }
#endif

    {
        std::lock_guard<std::mutex> lock(getApplicationLogMutex());
        std::cout << "Enter password:" << std::endl;
    }
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
}

int main() {
#if defined(_WIN32)
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
#endif

    std::string pathInput;
    std::string action;
    std::string password;

    {
        std::lock_guard<std::mutex> lock(getApplicationLogMutex());
        std::cout << "Enter file or directory path:" << std::endl;
    }
    std::getline(std::cin, pathInput);

    {
        std::lock_guard<std::mutex> lock(getApplicationLogMutex());
        std::cout << "Enter action (ENCRYPT/DECRYPT):" << std::endl;
    }
    std::cin >> action;
    action = toUpper(action);

    if (action != "ENCRYPT" && action != "DECRYPT") {
        std::cerr << "Invalid action. Must be ENCRYPT or DECRYPT." << std::endl;
        return 1;
    }

    { std::string discard; std::getline(std::cin, discard); }

    if (!readPasswordMasked(password) || password.empty()) {
        std::cerr << "Password cannot be empty." << std::endl;
        return 1;
    }

    bool preserveOriginals = true;
    if (action == "ENCRYPT") {
        std::cout << "Delete original files after encryption? (y/N): ";
        std::string choice;
        std::getline(std::cin, choice);
        if (!choice.empty() && (choice[0] == 'y' || choice[0] == 'Y')) {
            preserveOriginals = false;
        }
    }

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

    std::size_t chunkSizeKB = 256;
    if (action == "ENCRYPT") {
        std::cout << "Enter chunk size in KB (default 256): ";
        std::string chunkInput;
        std::getline(std::cin, chunkInput);
        try {
            if (!chunkInput.empty()) {
                std::size_t parsed = std::stoull(chunkInput);
                if (parsed > 0) {
                    chunkSizeKB = parsed;
                }
            }
        } catch (...) {
            chunkSizeKB = 256;
        }
    }


    const fs::path target(pathInput);

    try {
        ProcessManagement pm(numWorkers, chunkSizeKB);
        int fileCount = 0;

        std::error_code isRegEc;
        if (fs::is_regular_file(target, isRegEc)) {
            if (shouldProcessFile(target, action)) {
                Action taskAction = (action == "ENCRYPT") ? Action::ENCRYPT : Action::DECRYPT;
                std::error_code szEc;
                const auto rawSize = fs::file_size(target, szEc);
                const std::uint64_t fsz = szEc ? 0 : static_cast<std::uint64_t>(rawSize);
                auto task = std::make_unique<Task>(taskAction, target, fsz);
                pm.submitToQueue(std::move(task));
                fileCount++;

                char sizeStr[20];
                if (fsz >= (std::uint64_t)1024*1024*1024)
                    std::snprintf(sizeStr, sizeof sizeStr, "%.2f GB", (double)fsz/(1024.0*1024*1024));
                else if (fsz >= (std::uint64_t)1024*1024)
                    std::snprintf(sizeStr, sizeof sizeStr, "%.2f MB", (double)fsz/(1024.0*1024));
                else
                    std::snprintf(sizeStr, sizeof sizeStr, "%.2f KB", (double)fsz/1024.0);
                std::cout << "Found: 1 file (" << sizeStr << ")\n\n";
            }
            const char* verb = (action == "ENCRYPT") ? "Encrypting" : "Decrypting";
            std::cout << verb << "...\n\n";
            const bool success = pm.executeTasks(password, preserveOriginals);
            scrubPassword(password);
            return success ? 0 : 1;
        }

        std::error_code isDirEc;
        if (fs::is_directory(target, isDirEc)) {
            std::cout << "Scanning directory...\n";
            std::error_code ec;
            fs::recursive_directory_iterator it(target, fs::directory_options::skip_permission_denied, ec);
            fs::recursive_directory_iterator end;
            std::uint64_t totalSizeForDisplay = 0;

            for (; it != end; it.increment(ec)) {
                if (ec) {
                    std::cerr << "Warning: could not access a directory entry: " << ec.message() << '\n';
                    ec.clear();
                    continue;
                }

                try {
                    std::error_code entryEc;
                    const fs::directory_entry &entry = *it;
                    if (!entry.is_regular_file(entryEc)) {
                        if (entryEc) { entryEc.clear(); }
                        continue;
                    }

                    if (!shouldProcessFile(entry.path(), action)) {
                        continue;
                    }

                    Action taskAction = (action == "ENCRYPT") ? Action::ENCRYPT : Action::DECRYPT;
                    // directory_entry::file_size() returns the cached size — no extra stat() call.
                    std::error_code szEc;
                    const auto rawSize = entry.file_size(szEc);
                    const std::uint64_t fsz = szEc ? 0 : static_cast<std::uint64_t>(rawSize);
                    totalSizeForDisplay += fsz;
                    auto task = std::make_unique<Task>(taskAction, entry.path(), fsz);
                    pm.submitToQueue(std::move(task));
                    fileCount++;
                } catch (const std::exception &ex) {
                    std::cerr << "Warning: skipping problematic file: " << ex.what() << '\n';
                } catch (...) {
                    std::cerr << "Warning: skipping problematic file.\n";
                }
            }

            char sizeStr[20];
            if (totalSizeForDisplay >= (std::uint64_t)1024*1024*1024)
                std::snprintf(sizeStr, sizeof sizeStr, "%.2f GB", (double)totalSizeForDisplay/(1024.0*1024*1024));
            else if (totalSizeForDisplay >= (std::uint64_t)1024*1024)
                std::snprintf(sizeStr, sizeof sizeStr, "%.2f MB", (double)totalSizeForDisplay/(1024.0*1024));
            else
                std::snprintf(sizeStr, sizeof sizeStr, "%.2f KB", (double)totalSizeForDisplay/1024.0);

            std::cout << "Found: " << fileCount << " files (" << sizeStr << ")\n\n";
            const char* verb = (action == "ENCRYPT") ? "Encrypting" : "Decrypting";
            std::cout << verb << "...\n\n";
            const bool success = pm.executeTasks(password, preserveOriginals);
            scrubPassword(password);
            return success ? 0 : 1;
        }

        std::cerr << "Path does not exist or is not a regular file/directory." << std::endl;
        scrubPassword(password);
        return 1;
    } catch (const fs::filesystem_error &ex) {
        std::cerr << "Filesystem error: " << ex.what() << std::endl;
        scrubPassword(password);
        return 1;
    } catch (const std::exception &ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        scrubPassword(password);
        return 1;
    }
}
