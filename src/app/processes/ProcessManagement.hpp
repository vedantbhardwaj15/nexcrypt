#ifndef PROCESS_MANAGEMENT_HPP
#define PROCESS_MANAGEMENT_HPP

#include "ProgressReporter.hpp"
#include "Task.hpp"
#include <sodium.h>
#include <atomic>
#include <cstdint>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

inline std::mutex &getApplicationLogMutex() {
    static std::mutex mutex;
    return mutex;
}

class ProcessManagement {
    public:
        explicit ProcessManagement(int numWorkers = 4, std::size_t chunkSizeKB = 256);
        ~ProcessManagement();
        bool submitToQueue(std::unique_ptr<Task> task);
        bool executeTasks(const std::string &password, bool preserveOriginals);
        void shutdown();

        // Getters return uint64_t to match the underlying atomic type.
        std::uint64_t getFilesProcessed() const { return filesProcessed.load(std::memory_order_relaxed); }
        std::uint64_t getFailures()        const { return failures.load(std::memory_order_relaxed); }
        std::uint64_t getBytesProcessed()  const { return bytesProcessed.load(std::memory_order_relaxed); }
        double        getElapsedSeconds()  const { return elapsedTime; }
        int           getNumWorkers()      const { return numWorkers; }
        std::size_t   getChunkSizeKB()     const { return chunkSizeKB; }

    private:
        std::queue<std::unique_ptr<Task>> taskQueue;
        std::vector<std::thread>          workerThreads;
        std::mutex                        queueMutex;
        std::condition_variable           queueCV;
        std::atomic<bool>                 shutdown_flag{false};
        std::atomic<bool>                 submissionComplete{false};

        // --- Atomic counters written ONLY by workers via fetch_add(relaxed). ---
        // uint64_t avoids signed-overflow on large batch jobs.
        std::atomic<std::uint64_t> filesProcessed{0};
        std::atomic<std::uint64_t> failures{0};
        std::atomic<std::uint64_t> bytesProcessed{0};

        // --- Pre-computed totals (main thread only, written before workers start). ---
        // Plain (non-atomic): written in submitToQueue / read in executeTasks,
        // both on the main thread with no concurrent access at those points.
        std::uint64_t totalBytesAccum_{0}; // accumulated from Task::fileSize during submission

        double      elapsedTime{0.0};
        int         numWorkers;
        std::size_t chunkSizeKB;

        void workerFunc(const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES], bool preserveOriginals);
};

#endif