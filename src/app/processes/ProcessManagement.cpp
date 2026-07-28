#include "ProcessManagement.hpp"

#include "../encryptDecrypt/Cryption.hpp"

#include <chrono>
#include <filesystem>
#include <iomanip>
#include <iostream>

namespace fs = std::filesystem;

ProcessManagement::ProcessManagement(int numWorkers)
    : numWorkers(numWorkers <= 0 ? 4 : numWorkers) {}

ProcessManagement::~ProcessManagement() {
    shutdown();
}

bool ProcessManagement::submitToQueue(std::unique_ptr<Task> task) {
    if (!task) return false;
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        taskQueue.push(std::move(task));
    }
    queueCV.notify_one();
    return true;
}

void ProcessManagement::shutdown() {
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        shutdown_flag.store(true, std::memory_order_release);
    }
    queueCV.notify_all();

    for (std::thread &worker : workerThreads) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    workerThreads.clear();
}

bool ProcessManagement::executeTasks(const std::string &password, bool preserveOriginals) {
    filesProcessed.store(0, std::memory_order_relaxed);
    failures.store(0, std::memory_order_relaxed);
    bytesProcessed.store(0, std::memory_order_relaxed);
    shutdown_flag.store(false, std::memory_order_release);

    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    if (!deriveKeyFromPassword(password, key)) {
        std::cerr << "ERROR: Failed to derive encryption key from password." << std::endl;
        return false;
    }

    const auto startTime = std::chrono::high_resolution_clock::now();

    workerThreads.reserve(static_cast<std::size_t>(numWorkers));
    for (int i = 0; i < numWorkers; ++i) {
        workerThreads.emplace_back(&ProcessManagement::workerFunc, this, key, preserveOriginals);
    }

    submissionComplete.store(true, std::memory_order_release);
    queueCV.notify_all();

    for (std::thread &worker : workerThreads) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    workerThreads.clear();

    sodium_memzero(key, sizeof key);

    const auto endTime = std::chrono::high_resolution_clock::now();
    elapsedTime = std::chrono::duration<double>(endTime - startTime).count();

    const int totalProcessed = filesProcessed.load(std::memory_order_relaxed);
    const int totalFailures = failures.load(std::memory_order_relaxed);
    const std::uint64_t totalBytes = bytesProcessed.load(std::memory_order_relaxed);

    double bytesInKB = static_cast<double>(totalBytes) / 1024.0;
    double bytesInMB = bytesInKB / 1024.0;
    double bytesInGB = bytesInMB / 1024.0;

    std::cout << "\n==================================================" << std::endl;
    std::cout << "PROCESSING COMPLETE" << std::endl;
    std::cout << "==================================================" << std::endl;
    std::cout << "Files processed:    " << totalProcessed << std::endl;
    std::cout << "Failures:           " << totalFailures << std::endl;

    if (bytesInGB >= 1.0) {
        std::cout << std::fixed << std::setprecision(2) << "Data processed:     " << bytesInGB << " GB" << std::endl;
    } else if (bytesInMB >= 1.0) {
        std::cout << std::fixed << std::setprecision(2) << "Data processed:     " << bytesInMB << " MB" << std::endl;
    } else {
        std::cout << std::fixed << std::setprecision(2) << "Data processed:     " << bytesInKB << " KB" << std::endl;
    }

    std::cout << "Worker threads:     " << numWorkers << std::endl;
    std::cout << std::fixed << std::setprecision(2) << "Total time:         " << elapsedTime << " seconds" << std::endl;

    if (elapsedTime > 0.0) {
        const double throughputFiles = static_cast<double>(totalProcessed) / elapsedTime;
        const double throughputMB = (static_cast<double>(totalBytes) / (1024.0 * 1024.0)) / elapsedTime;
        std::cout << std::fixed << std::setprecision(2) << "Throughput:         " << throughputFiles << " files/sec" << std::endl;
        std::cout << std::fixed << std::setprecision(2) << "Data throughput:    " << throughputMB << " MB/s" << std::endl;
    }
    std::cout << "==================================================" << std::endl;

    return totalFailures == 0;
}

void ProcessManagement::workerFunc(const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES], bool preserveOriginals) {
    while (true) {
        std::unique_ptr<Task> taskToExecute;
        {
            std::unique_lock<std::mutex> lock(queueMutex);
            queueCV.wait(lock, [this] {
                return !taskQueue.empty() ||
                       shutdown_flag.load(std::memory_order_acquire) ||
                       submissionComplete.load(std::memory_order_acquire);
            });

            if (taskQueue.empty()) {
                if (shutdown_flag.load(std::memory_order_acquire) ||
                    submissionComplete.load(std::memory_order_acquire)) {
                    break;
                }
                continue;
            }

            taskToExecute = std::move(taskQueue.front());
            taskQueue.pop();
        }

        if (!taskToExecute) {
            continue;
        }

        const fs::path &inputPath = taskToExecute->filePath;
        fs::path outputPath;
        bool success = false;

        std::error_code sizeEc;
        const auto fileSize = fs::file_size(inputPath, sizeEc);
        const std::uint64_t inputSize = sizeEc ? 0 : static_cast<std::uint64_t>(fileSize);

        try {
            if (taskToExecute->action == Action::ENCRYPT) {
                outputPath = fs::path(inputPath.native() + fs::path(".nex").native());
                {
                    std::lock_guard<std::mutex> lock(getApplicationLogMutex());
                    std::cout << "[Worker] Encrypting: " << inputPath.filename().string() << std::endl;
                }
                success = encryptFile(inputPath, outputPath, key);

                if (!success) {
                    std::error_code removeEc;
                    fs::remove(outputPath, removeEc);
                } else if (!preserveOriginals) {
                    std::error_code removeEc;
                    fs::remove(inputPath, removeEc);
                }
            } else {
                outputPath = inputPath;
                outputPath.replace_extension("");
                {
                    std::lock_guard<std::mutex> lock(getApplicationLogMutex());
                    std::cout << "[Worker] Decrypting: " << inputPath.filename().string() << std::endl;
                }
                success = decryptFile(inputPath, outputPath, key);

                if (!success) {
                    std::error_code removeEc;
                    fs::remove(outputPath, removeEc);
                } else {
                    std::error_code removeEc;
                    fs::remove(inputPath, removeEc);
                }
            }
        } catch (const std::exception &ex) {
            std::lock_guard<std::mutex> lock(getApplicationLogMutex());
            std::cerr << "[Warning] Skipping file due to error: " << ex.what() << std::endl;
            success = false;
        } catch (...) {
            std::lock_guard<std::mutex> lock(getApplicationLogMutex());
            std::cerr << "[Warning] Skipping file due to unknown exception." << std::endl;
            success = false;
        }

        if (success) {
            filesProcessed.fetch_add(1, std::memory_order_relaxed);
            bytesProcessed.fetch_add(inputSize, std::memory_order_relaxed);
        } else {
            failures.fetch_add(1, std::memory_order_relaxed);
            std::lock_guard<std::mutex> lock(getApplicationLogMutex());
            std::cerr << "ERROR: Failed to process file: " << inputPath.string() << std::endl;
        }
    }
}
