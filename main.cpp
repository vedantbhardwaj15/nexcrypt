#include <algorithm>
#include <cctype>
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

    {
        std::lock_guard<std::mutex> lock(getApplicationLogMutex());
        std::cout << "Using " << numWorkers << " parallel worker threads with " << chunkSizeKB << " KB chunk size." << std::endl;
    }

    const fs::path target(pathInput);

    try {
        ProcessManagement pm(numWorkers, chunkSizeKB);
        int fileCount = 0;

        std::error_code isRegEc;
        if (fs::is_regular_file(target, isRegEc)) {
            if (shouldProcessFile(target, action)) {
                Action taskAction = (action == "ENCRYPT") ? Action::ENCRYPT : Action::DECRYPT;
                auto task = std::make_unique<Task>(taskAction, target);
                pm.submitToQueue(std::move(task));
                fileCount++;
            }
            const bool success = pm.executeTasks(password, preserveOriginals);
            scrubPassword(password);
            return success ? 0 : 1;
        }

        std::error_code isDirEc;
        if (fs::is_directory(target, isDirEc)) {
            std::error_code ec;
            fs::recursive_directory_iterator it(target, fs::directory_options::skip_permission_denied, ec);
            fs::recursive_directory_iterator end;

            for (; it != end; it.increment(ec)) {
                if (ec) {
                    std::lock_guard<std::mutex> lock(getApplicationLogMutex());
                    std::cerr << "Warning: could not access a directory entry: " << ec.message() << std::endl;
                    ec.clear();
                    continue;
                }

                try {
                    std::error_code entryEc;
                    const fs::directory_entry &entry = *it;
                    if (!entry.is_regular_file(entryEc)) {
                        if (entryEc) {
                            entryEc.clear();
                        }
                        continue;
                    }

                    if (!shouldProcessFile(entry.path(), action)) {
                        continue;
                    }

                    Action taskAction = (action == "ENCRYPT") ? Action::ENCRYPT : Action::DECRYPT;
                    auto task = std::make_unique<Task>(taskAction, entry.path());
                    pm.submitToQueue(std::move(task));
                    fileCount++;
                } catch (const std::exception &ex) {
                    std::lock_guard<std::mutex> lock(getApplicationLogMutex());
                    std::cerr << "Warning: skipping problematic file: " << ex.what() << std::endl;
                } catch (...) {
                    std::lock_guard<std::mutex> lock(getApplicationLogMutex());
                    std::cerr << "Warning: skipping problematic file." << std::endl;
                }
            }

            {
                std::lock_guard<std::mutex> lock(getApplicationLogMutex());
                std::cout << "Submitted " << fileCount << " files for processing." << std::endl;
            }
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
