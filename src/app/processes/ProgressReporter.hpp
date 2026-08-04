#ifndef PROGRESS_REPORTER_HPP
#define PROGRESS_REPORTER_HPP

// ProgressReporter — dedicated progress-display thread for Nexcrypt.
//
// Design constraints (enforced by this interface):
//  - Worker threads NEVER call into this class.
//  - All timing, formatting, and math live exclusively in run().
//  - The only coupling to workers is via three atomic<uint64_t> references
//    that workers already update with fetch_add(relaxed).
//  - Zero heap allocations in the render loop (stack char[] only).
//  - RAII: destructor calls stop(), exception-safe.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <thread>

class ProgressReporter {
public:
    // totalFiles / totalBytes must be pre-computed on the main thread BEFORE
    // workers start.  They are stored as const and never re-computed.
    ProgressReporter(std::uint64_t                      totalFiles,
                     std::uint64_t                      totalBytes,
                     const std::atomic<std::uint64_t>&  filesProcessed,
                     const std::atomic<std::uint64_t>&  bytesProcessed,
                     const std::atomic<std::uint64_t>&  failures) noexcept;

    // RAII: calls stop() if still running.
    ~ProgressReporter();

    // Non-copyable, non-movable — owns a thread and CV.
    ProgressReporter(const ProgressReporter&)            = delete;
    ProgressReporter& operator=(const ProgressReporter&) = delete;
    ProgressReporter(ProgressReporter&&)                 = delete;
    ProgressReporter& operator=(ProgressReporter&&)      = delete;

    // Launch the progress thread.  Must be called before workers start.
    void start();

    // Signal stop, wake the thread immediately, join.
    // Idempotent — safe to call more than once or from the destructor.
    // Prints a final render + newline before returning so the terminal is clean.
    void stop();

private:
    // Entry point for the progress thread.
    void run() noexcept;

    // Precomputed totals (immutable after construction — no locks needed).
    const std::uint64_t totalFiles_;
    const std::uint64_t totalBytes_;

    // References to worker-owned atomics — read with relaxed ordering only.
    const std::atomic<std::uint64_t>& filesProcessed_;
    const std::atomic<std::uint64_t>& bytesProcessed_;
    const std::atomic<std::uint64_t>& failures_;

    // Captured once at construction — never written again.
    const std::chrono::steady_clock::time_point startTime_;

    // Shutdown flag and condvar for instant wakeup on stop().
    // running_ is written under mtx_ so the predicate in wait_for is race-free.
    std::atomic<bool>       running_{false};
    std::mutex              mtx_;
    std::condition_variable cv_;
    std::thread             thread_;
};

#endif // PROGRESS_REPORTER_HPP
