#ifndef PROCESS_MANAGEMENT_HPP
#define PROCESS_MANAGEMENT_HPP

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
        explicit ProcessManagement(int numWorkers = 4);
        ~ProcessManagement();
        bool submitToQueue(std::unique_ptr<Task> task);
        bool executeTasks(const std::string &password, bool preserveOriginals);
        void shutdown();

        int getFilesProcessed() const { return filesProcessed.load(std::memory_order_relaxed); }
        int getFailures() const { return failures.load(std::memory_order_relaxed); }
        std::uint64_t getBytesProcessed() const { return bytesProcessed.load(std::memory_order_relaxed); }
        double getElapsedSeconds() const { return elapsedTime; }
        int getNumWorkers() const { return numWorkers; }

    private:
        std::queue<std::unique_ptr<Task>> taskQueue;
        std::vector<std::thread> workerThreads;
        std::mutex queueMutex;
        std::condition_variable queueCV;
        std::atomic<bool> shutdown_flag{false};
        std::atomic<bool> submissionComplete{false};
        std::atomic<int> filesProcessed{0};
        std::atomic<int> failures{0};
        std::atomic<std::uint64_t> bytesProcessed{0};
        double elapsedTime{0.0};
        int numWorkers;

        void workerFunc(const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES], bool preserveOriginals);
};

#endif