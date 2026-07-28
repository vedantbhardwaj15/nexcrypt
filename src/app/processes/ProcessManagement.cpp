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

    // Start workers FIRST so they can begin draining the queue
    for (int i = 0; i < numWorkers; ++i) {
        workerThreads.emplace_back(&ProcessManagement::workerFunc, this, password, preserveOriginals);
    }

    // THEN signal that no more tasks will be submitted
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
        std::cout << "Files processed:    " << getFilesProcessed() << std::endl;
        std::cout << "Failures:           " << getFailures() << std::endl;
        std::cout << "Worker threads:     " << numWorkers << std::endl;
        std::cout << "Total time:         " << std::fixed << std::setprecision(2)
                  << elapsedTime << " seconds" << std::endl;

        if (getFilesProcessed() > 0 && elapsedTime > 0.0) {
            const double throughput = static_cast<double>(getFilesProcessed()) / elapsedTime;
            std::cout << "Throughput:         " << std::fixed << std::setprecision(2)
                      << throughput << " files/sec" << std::endl;
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

        try {
            if (taskToExecute->action == Action::ENCRYPT) {
                outputPath = fs::path(inputPath.native() + fs::path(".nex").native());
                {
                    std::lock_guard<std::mutex> lock(getApplicationLogMutex());
                    std::cout << "[Worker] Encrypting: " << inputPath.filename() << std::endl;
                }
                success = encryptFile(inputPath, outputPath, password);

                if (!success) {
                    std::error_code removeEc;
                    fs::remove(outputPath, removeEc);
                    if (removeEc) {
                        std::lock_guard<std::mutex> lock(getApplicationLogMutex());
                        std::cerr << "Warning: could not remove partial output '" << outputPath << "': "
                                  << removeEc.message() << std::endl;
                    }
                } else if (!preserveOriginals) {
                    std::error_code removeEc;
                    fs::remove(inputPath, removeEc);
                    if (removeEc) {
                        std::lock_guard<std::mutex> lock(getApplicationLogMutex());
                        std::cerr << "Warning: could not remove original file '" << inputPath << "': "
                                  << removeEc.message() << std::endl;
                    }
                }
            } else {
                outputPath = inputPath;
                outputPath.replace_extension("");
                {
                    std::lock_guard<std::mutex> lock(getApplicationLogMutex());
                    std::cout << "[Worker] Decrypting: " << inputPath.filename() << std::endl;
                }
                success = decryptFile(inputPath, outputPath, password);

                if (!success) {
                    std::error_code removeEc;
                    fs::remove(outputPath, removeEc);
                    if (removeEc) {
                        std::lock_guard<std::mutex> lock(getApplicationLogMutex());
                        std::cerr << "Warning: could not remove partial output '" << outputPath << "': "
                                  << removeEc.message() << std::endl;
                    }
                } else {
                    std::error_code removeEc;
                    fs::remove(inputPath, removeEc);
                    if (removeEc) {
                        std::lock_guard<std::mutex> lock(getApplicationLogMutex());
                        std::cerr << "Warning: could not remove encrypted file '" << inputPath << "': "
                                  << removeEc.message() << std::endl;
                    }
                }
            }
        } catch (const std::exception &ex) {
            std::cerr << "Worker exception while processing '" << inputPath << "': " << ex.what() << std::endl;
        } catch (...) {
            std::cerr << "Worker encountered an unknown exception while processing '" << inputPath << "'" << std::endl;
        }

        if (success) {
            filesProcessed.fetch_add(1, std::memory_order_relaxed);
        } else {
            failures.fetch_add(1, std::memory_order_relaxed);
            std::lock_guard<std::mutex> lock(getApplicationLogMutex());
            std::cerr << "ERROR: Failed to process " << inputPath << std::endl;
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
