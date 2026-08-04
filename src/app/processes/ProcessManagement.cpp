#include "ProcessManagement.hpp"

#include "../encryptDecrypt/Cryption.hpp"
#include "ProgressReporter.hpp"

#include <chrono>
#include <filesystem>
#include <iomanip>
#include <iostream>

namespace fs = std::filesystem;

ProcessManagement::ProcessManagement(int numWorkers, std::size_t chunkSizeKB)
    : numWorkers(numWorkers <= 0 ? 4 : numWorkers),
      chunkSizeKB(chunkSizeKB == 0 ? 256 : chunkSizeKB) {}

ProcessManagement::~ProcessManagement() {
    shutdown();
}

bool ProcessManagement::submitToQueue(std::unique_ptr<Task> task) {
    if (!task) return false;
    // Accumulate file size on the main thread before workers start.
    // This is the only place totalBytesAccum_ is written; no lock needed.
    totalBytesAccum_ += task->fileSize;
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
    // Reset worker-written atomics.
    filesProcessed.store(0, std::memory_order_relaxed);
    failures.store(0, std::memory_order_relaxed);
    bytesProcessed.store(0, std::memory_order_relaxed);
    shutdown_flag.store(false, std::memory_order_release);

    // Pre-compute totals on the main thread BEFORE any worker starts.
    // Workers never touch these values.

    // taskQueue has not been touched by any worker yet (they haven't started),
    // so reading its size without the mutex is safe at this point.
    const std::uint64_t totalFiles = static_cast<std::uint64_t>(taskQueue.size());
    const std::uint64_t totalBytes = totalBytesAccum_;
    totalBytesAccum_ = 0; // reset for potential reuse

    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    if (!deriveKeyFromPassword(password, key)) {
        std::cerr << "ERROR: Failed to derive encryption key from password." << '\n';
        return false;
    }

    const auto startTime = std::chrono::high_resolution_clock::now();

    
    // Construct ProgressReporter and start it BEFORE spawning workers.
    // It holds const-refs to our atomics and the precomputed totals.
    // RAII: reporter.stop() is called explicitly after join; the destructor
    // is a no-op by that point.
    
    ProgressReporter reporter(totalFiles, totalBytes,
                              filesProcessed, bytesProcessed, failures);
    reporter.start();

    // ---------------------------------------------------------------------------
    // Spawn worker threads — workerFunc is NOT modified in any way.
    // ---------------------------------------------------------------------------
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

    // All workers have finished.  Stop the progress thread (prints final bar + \n).
    reporter.stop();

    sodium_memzero(key, sizeof key);

    const auto endTime = std::chrono::high_resolution_clock::now();
    elapsedTime = std::chrono::duration<double>(endTime - startTime).count();

    const std::uint64_t totalProcessed = filesProcessed.load(std::memory_order_relaxed);
    const std::uint64_t totalFailures  = failures.load(std::memory_order_relaxed);
    const std::uint64_t totalBytesProc = bytesProcessed.load(std::memory_order_relaxed);

    const double bytesInKB = static_cast<double>(totalBytesProc) / 1024.0;
    const double bytesInMB = bytesInKB / 1024.0;
    const double bytesInGB = bytesInMB / 1024.0;

    std::cout << "\n==================================================\n";
    std::cout << "PROCESSING COMPLETE\n";
    std::cout << "==================================================\n";

    // Format data processed in human-readable units.
    char dataBuf[20];
    if (bytesInGB >= 1.0)
        std::snprintf(dataBuf, sizeof dataBuf, "%.2f GB", bytesInGB);
    else if (bytesInMB >= 1.0)
        std::snprintf(dataBuf, sizeof dataBuf, "%.2f MB", bytesInMB);
    else
        std::snprintf(dataBuf, sizeof dataBuf, "%.2f KB", bytesInKB);

    std::cout << std::left;
    std::cout << std::setw(16) << "Files processed" << ": " << totalProcessed << '\n';
    std::cout << std::setw(16) << "Failures"        << ": " << totalFailures  << '\n';
    std::cout << std::setw(16) << "Data processed"  << ": " << dataBuf        << '\n';
    std::cout << std::setw(16) << "Worker threads"  << ": " << numWorkers     << '\n';
    std::cout << std::setw(16) << "Chunk size"      << ": " << chunkSizeKB    << " KB\n";
    std::cout << std::fixed << std::setprecision(1);
    std::cout << std::setw(16) << "Time"            << ": " << elapsedTime    << " s\n";
    if (elapsedTime > 0.0) {
        const double throughputMB = (static_cast<double>(totalBytesProc) / (1024.0 * 1024.0)) / elapsedTime;
        std::cout << std::setw(16) << "Throughput"  << ": " << throughputMB   << " MB/s\n";
    }
    std::cout << "==================================================\n";

    return totalFailures == 0;
}

void ProcessManagement::workerFunc(const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES], bool preserveOriginals) {
    // Pre-allocate I/O buffers ONCE per worker thread using runtime chunk size
    const std::size_t plainSize = chunkSizeKB * 1024;
    const std::size_t cipherSize = plainSize + crypto_secretstream_xchacha20poly1305_ABYTES;
    std::vector<unsigned char> plainBuf(plainSize);
    std::vector<unsigned char> cipherBuf(cipherSize);

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

        try {
            const fs::path &inputPath = taskToExecute->filePath;
            fs::path outputPath;
            bool success = false;

            if (taskToExecute->action == Action::ENCRYPT) {
                outputPath = fs::path(inputPath.native() + fs::path(".nex").native());
                success = encryptFile(inputPath, outputPath, key, plainBuf, cipherBuf, &bytesProcessed);

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
                success = decryptFile(inputPath, outputPath, key, cipherBuf, plainBuf, &bytesProcessed);

                if (!success) {
                    std::error_code removeEc;
                    fs::remove(outputPath, removeEc);
                } else {
                    std::error_code removeEc;
                    fs::remove(inputPath, removeEc);
                }
            }

            if (success) {
                filesProcessed.fetch_add(1, std::memory_order_relaxed);
            } else {
                failures.fetch_add(1, std::memory_order_relaxed);
                std::lock_guard<std::mutex> lock(getApplicationLogMutex());
                std::cerr << "ERROR: Failed to process file: " << safePathString(inputPath) << '\n';
            }
        } catch (const std::exception &ex) {
            failures.fetch_add(1, std::memory_order_relaxed);
            std::lock_guard<std::mutex> lock(getApplicationLogMutex());
            std::cerr << "[Warning] Skipping file due to error: " << ex.what() << '\n';
        } catch (...) {
            failures.fetch_add(1, std::memory_order_relaxed);
            std::lock_guard<std::mutex> lock(getApplicationLogMutex());
            std::cerr << "[Warning] Skipping file due to unknown exception." << '\n';
        }
    }
}
