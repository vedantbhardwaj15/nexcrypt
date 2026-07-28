#include "ProcessManagement.hpp"

#include "../encryptDecrypt/Cryption.hpp"

#include <chrono>
#include <filesystem>
#include <iomanip>
#include <iostream>

namespace fs = std::filesystem;

ProcessManagement::ProcessManagement(int numWorkers)
    : numWorkers(numWorkers) {}

ProcessManagement::~ProcessManagement() {
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        if (!taskQueue.empty()) {
            std::cerr << "Warning: " << taskQueue.size()
                      << " task(s) were left queued and will be discarded." << std::endl;
        }
    }
    shutdown();
}

bool ProcessManagement::submitToQueue(std::unique_ptr<Task> task) {
    if (!task) {
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(queueMutex);
        taskQueue.push(std::move(task));
    }
    queueCV.notify_one();
    return true;
}

bool ProcessManagement::executeTasks(const std::string &password, bool preserveOriginals) {
    auto startTime = std::chrono::high_resolution_clock::now();

    // spawn workers before marking submission complete to avoid premature thread exit
    for (int i = 0; i < numWorkers; ++i) {
        workerThreads.emplace_back(&ProcessManagement::workerFunc, this, password, preserveOriginals);
    }

    // release memory order ensures workers see queued items before seeing submissionComplete
    submissionComplete.store(true, std::memory_order_release);
    queueCV.notify_all();

    for (auto &thread : workerThreads) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    elapsedTime = std::chrono::duration<double>(endTime - startTime).count();
    workerThreads.clear();

    {
        std::lock_guard<std::mutex> lock(getApplicationLogMutex());
        std::cout << "\n" << std::string(50, '=') << std::endl;
        std::cout << "PROCESSING COMPLETE" << std::endl;
        std::cout << std::string(50, '=') << std::endl;
        const auto totalBytes = getBytesProcessed();
        std::cout << "Files processed:    " << getFilesProcessed() << std::endl;
        std::cout << "Failures:           " << getFailures() << std::endl;

        if (totalBytes < 1024ULL * 1024ULL) {
            std::cout << "Data processed:     " << std::fixed << std::setprecision(2)
                      << static_cast<double>(totalBytes) / 1024.0 << " KB" << std::endl;
        } else if (totalBytes < 1024ULL * 1024ULL * 1024ULL) {
            std::cout << "Data processed:     " << std::fixed << std::setprecision(2)
                      << static_cast<double>(totalBytes) / (1024.0 * 1024.0) << " MB" << std::endl;
        } else {
            std::cout << "Data processed:     " << std::fixed << std::setprecision(2)
                      << static_cast<double>(totalBytes) / (1024.0 * 1024.0 * 1024.0) << " GB" << std::endl;
        }

        std::cout << "Worker threads:     " << numWorkers << std::endl;
        std::cout << "Total time:         " << std::fixed << std::setprecision(2)
                  << elapsedTime << " seconds" << std::endl;

        if (getFilesProcessed() > 0 && elapsedTime > 0.0) {
            const double fileThroughput = static_cast<double>(getFilesProcessed()) / elapsedTime;
            std::cout << "Throughput:         " << std::fixed << std::setprecision(2)
                      << fileThroughput << " files/sec" << std::endl;

            if (totalBytes > 0) {
                const double mbPerSec = static_cast<double>(totalBytes) / (1024.0 * 1024.0) / elapsedTime;
                std::cout << "Data throughput:    " << std::fixed << std::setprecision(2)
                          << mbPerSec << " MB/s" << std::endl;
            }
        }
        std::cout << std::string(50, '=') << std::endl;
    }

    return getFailures() == 0;
}

void ProcessManagement::workerFunc(const std::string &password, bool preserveOriginals) {
    while (true) {
        std::unique_ptr<Task> taskToExecute;

        {
            std::unique_lock<std::mutex> lock(queueMutex);
            queueCV.wait(lock, [this]() {
                return !taskQueue.empty() || submissionComplete.load(std::memory_order_acquire)
                    || shutdown_flag.load(std::memory_order_acquire);
            });

            // exit condition: queue fully drained and producer is done
            if (taskQueue.empty()) {
                if (submissionComplete.load(std::memory_order_acquire) || shutdown_flag.load(std::memory_order_acquire)) {
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

        const fs::path inputPath(taskToExecute->filePath);
        fs::path outputPath;
        bool success = false;

        // use non-throwing overload to avoid crashing worker if file access fails
        std::error_code sizeEc;
        const auto fileSize = fs::file_size(inputPath, sizeEc);
        const std::uint64_t inputSize = sizeEc ? 0 : static_cast<std::uint64_t>(fileSize);

        try {
            if (taskToExecute->action == Action::ENCRYPT) {
                // native() avoids losing unicode characters on windows wide paths
                outputPath = fs::path(inputPath.native() + fs::path(".nex").native());
                {
                    std::lock_guard<std::mutex> lock(getApplicationLogMutex());
                    std::cout << "[Worker] Encrypting: " << inputPath.filename().u8string() << std::endl;
                }
                success = encryptFile(inputPath, outputPath, password);

                if (!success) {
                    std::error_code removeEc;
                    fs::remove(outputPath, removeEc);
                    if (removeEc) {
                        std::lock_guard<std::mutex> lock(getApplicationLogMutex());
                        std::cerr << "Warning: could not remove partial output '" << outputPath.u8string() << "': "
                                  << removeEc.message() << std::endl;
                    }
                } else if (!preserveOriginals) {
                    std::error_code removeEc;
                    fs::remove(inputPath, removeEc);
                    if (removeEc) {
                        std::lock_guard<std::mutex> lock(getApplicationLogMutex());
                        std::cerr << "Warning: could not remove original file '" << inputPath.u8string() << "': "
                                  << removeEc.message() << std::endl;
                    }
                }
            } else {
                outputPath = inputPath;
                outputPath.replace_extension("");
                {
                    std::lock_guard<std::mutex> lock(getApplicationLogMutex());
                    std::cout << "[Worker] Decrypting: " << inputPath.filename().u8string() << std::endl;
                }
                success = decryptFile(inputPath, outputPath, password);

                if (!success) {
                    std::error_code removeEc;
                    fs::remove(outputPath, removeEc);
                    if (removeEc) {
                        std::lock_guard<std::mutex> lock(getApplicationLogMutex());
                        std::cerr << "Warning: could not remove partial output '" << outputPath.u8string() << "': "
                                  << removeEc.message() << std::endl;
                    }
                } else {
                    std::error_code removeEc;
                    fs::remove(inputPath, removeEc);
                    if (removeEc) {
                        std::lock_guard<std::mutex> lock(getApplicationLogMutex());
                        std::cerr << "Warning: could not remove encrypted file '" << inputPath.u8string() << "': "
                                  << removeEc.message() << std::endl;
                    }
                }
            }
        } catch (const std::exception &ex) {
            std::cerr << "Worker exception while processing '" << inputPath.u8string() << "': " << ex.what() << std::endl;
        } catch (...) {
            std::cerr << "Worker encountered an unknown exception while processing '" << inputPath.u8string() << "'" << std::endl;
        }

        if (success) {
            filesProcessed.fetch_add(1, std::memory_order_relaxed);
            bytesProcessed.fetch_add(inputSize, std::memory_order_relaxed);
        } else {
            failures.fetch_add(1, std::memory_order_relaxed);
            std::lock_guard<std::mutex> lock(getApplicationLogMutex());
            std::cerr << "ERROR: Failed to process " << inputPath.u8string() << std::endl;
        }
    }
}

void ProcessManagement::shutdown() {
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        shutdown_flag.store(true, std::memory_order_release);
        submissionComplete.store(true, std::memory_order_release);
    }
    queueCV.notify_all();
}
