#include "ProgressReporter.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>

namespace {

constexpr int BAR_CELLS = 20;

// UTF-8: U+2588 FULL BLOCK / U+2591 LIGHT SHADE — each exactly 3 bytes.
constexpr char FILLED_BYTES[4] = "\xe2\x96\x88"; // █
constexpr char EMPTY_BYTES[4]  = "\xe2\x96\x91"; // ░

// Build a BAR_CELLS-wide Unicode progress bar into `out` (must be ≥ BAR_CELLS*3+32 bytes).
// Returns byte length written (not counting the null terminator).
int buildBar(char* out, int filledCells) noexcept {
    char* p = out;
    if (filledCells > 0) {
        std::memcpy(p, "\033[36m", 5); // Cyan for filled portion
        p += 5;
        for (int i = 0; i < filledCells; ++i) {
            p[0] = FILLED_BYTES[0]; p[1] = FILLED_BYTES[1]; p[2] = FILLED_BYTES[2];
            p += 3;
        }
    }
    if (filledCells < BAR_CELLS) {
        std::memcpy(p, "\033[90m", 5); // Muted gray for empty portion
        p += 5;
        for (int i = filledCells; i < BAR_CELLS; ++i) {
            p[0] = EMPTY_BYTES[0]; p[1] = EMPTY_BYTES[1]; p[2] = EMPTY_BYTES[2];
            p += 3;
        }
    }
    std::memcpy(p, "\033[0m", 4); // Reset
    p += 4;
    *p = '\0';
    return static_cast<int>(p - out);
}

// Format a duration (seconds) into a compact string.  `buf` must be ≥ 16 bytes.
int fmtTime(char* buf, std::size_t bufSize, double seconds) noexcept {
    if (seconds < 0.0) seconds = 0.0;
    const int s = static_cast<int>(seconds);
    if (s >= 3600) return std::snprintf(buf, bufSize, "%dh%02dm", s / 3600, (s % 3600) / 60);
    if (s >= 60)   return std::snprintf(buf, bufSize, "%dm%02ds", s / 60, s % 60);
    return std::snprintf(buf, bufSize, "%ds", s);
}

} // anonymous namespace

// ---------------------------------------------------------------------------

ProgressReporter::ProgressReporter(
        std::uint64_t                      totalFiles,
        std::uint64_t                      totalBytes,
        const std::atomic<std::uint64_t>&  filesProcessed,
        const std::atomic<std::uint64_t>&  bytesProcessed,
        const std::atomic<std::uint64_t>&  failures) noexcept
    : totalFiles_(totalFiles)
    , totalBytes_(totalBytes)
    , filesProcessed_(filesProcessed)
    , bytesProcessed_(bytesProcessed)
    , failures_(failures)
    , startTime_(std::chrono::steady_clock::now())
{}

ProgressReporter::~ProgressReporter() {
    stop();
}

void ProgressReporter::start() {
    {
        std::lock_guard<std::mutex> lock(mtx_);
        running_.store(true, std::memory_order_relaxed);
    }
    thread_ = std::thread(&ProgressReporter::run, this);
}

void ProgressReporter::stop() {
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (!running_.load(std::memory_order_relaxed)) return;
        running_.store(false, std::memory_order_relaxed);
    }
    cv_.notify_one();
    if (thread_.joinable()) thread_.join();
}

// ---------------------------------------------------------------------------
// run() — progress thread only.
//
// Per-iteration cost (entirely off the worker hot path):
//   3× atomic load (relaxed)
//   1× steady_clock::now()
//   ~6× snprintf into stack buffers
//   1× fwrite + fflush (only when output changes)
//   1× cv::wait_for(500ms)  ← sleeps; zero CPU
// ---------------------------------------------------------------------------
void ProgressReporter::run() noexcept {
    // Stack-only storage — zero heap in the render loop.
    char lineBuf[512];
    char prevBuf[512];
    prevBuf[0] = '\0';

    char barBuf[BAR_CELLS * 3 + 32]; // UTF-8 bar with ANSI color escapes
    char dataBuf[40];                // "X.XX/Y.YY GB"
    char tputStr[20];                // "XXX.X MB/s"
    char elapsedStr[16];             // "XXs" / "Xm00s"

    int prevByteLen = 0;

    // -----------------------------------------------------------------------
    // Precompute the data unit from totalBytes_ — it never changes, so we
    // pick it once and reuse it every render instead of re-evaluating.
    // -----------------------------------------------------------------------
    const char*  unitStr;
    double       unitDiv;
    if      (totalBytes_ >= static_cast<std::uint64_t>(1024) * 1024 * 1024) { unitStr = "GB"; unitDiv = 1024.0 * 1024.0 * 1024.0; }
    else if (totalBytes_ >= static_cast<std::uint64_t>(1024) * 1024)        { unitStr = "MB"; unitDiv = 1024.0 * 1024.0; }
    else if (totalBytes_ >= 1024ULL)                                         { unitStr = "KB"; unitDiv = 1024.0; }
    else                                                                      { unitStr = "B";  unitDiv = 1.0; }

    // -----------------------------------------------------------------------
    // Render lambda — called once per wakeup and once at final stop.
    // -----------------------------------------------------------------------
    auto render = [&]() noexcept {
        // 1. Snapshot atomics — relaxed: only this thread reads them for display.
        const std::uint64_t files = filesProcessed_.load(std::memory_order_relaxed);
        const std::uint64_t bytes = bytesProcessed_.load(std::memory_order_relaxed);
        const std::uint64_t fails = failures_.load(std::memory_order_relaxed);

        // 2. Elapsed time.
        const double elapsed = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - startTime_).count();

        // 3. Percentage (based on bytes processed for smooth progress during large files).
        double pct = 0.0;
        if (totalBytes_ > 0) {
            pct = 100.0 * static_cast<double>(bytes) / static_cast<double>(totalBytes_);
        } else if (totalFiles_ > 0) {
            pct = 100.0 * static_cast<double>(files) / static_cast<double>(totalFiles_);
        }
        if (pct > 100.0) pct = 100.0;
        if (pct < 0.0)   pct = 0.0;

        // 4. Throughput.
        const double throughputMBps = (elapsed > 0.001)
            ? static_cast<double>(bytes) / elapsed / (1024.0 * 1024.0)
            : 0.0;

        // 5. Bar (based on bytes processed).
        int filledCells = 0;
        if (totalBytes_ > 0) {
            filledCells = static_cast<int>(static_cast<double>(BAR_CELLS) * static_cast<double>(bytes) / static_cast<double>(totalBytes_));
        } else if (totalFiles_ > 0) {
            filledCells = static_cast<int>(static_cast<double>(BAR_CELLS) * static_cast<double>(files) / static_cast<double>(totalFiles_));
        }
        if (filledCells > BAR_CELLS) filledCells = BAR_CELLS;
        if (filledCells < 0)         filledCells = 0;

        buildBar(barBuf, filledCells);

        // 6. Data pair — consistent unit chosen from totalBytes_ at startup.
        std::snprintf(dataBuf, sizeof dataBuf, "%.2f/%.2f %s",
            static_cast<double>(bytes)        / unitDiv,
            static_cast<double>(totalBytes_)  / unitDiv,
            unitStr);

        // 7. Throughput string.
        if (throughputMBps >= 1.0)
            std::snprintf(tputStr, sizeof tputStr, "%.1f MB/s", throughputMBps);
        else
            std::snprintf(tputStr, sizeof tputStr, "%.1f KB/s", throughputMBps * 1024.0);

        // 8. Elapsed string.
        fmtTime(elapsedStr, sizeof elapsedStr, elapsed);

        // 9. Assemble full line with mature, high-contrast CLI styling.
        // Format: [bar] PCT% | N/N | X.XX/Y.YY UNIT | TPUT | ELAPSEDs
        const int byteLen = std::snprintf(lineBuf, sizeof lineBuf,
            "\033[90m[\033[0m%s\033[90m]\033[0m \033[1m%3.0f%%\033[0m \033[90m|\033[0m %llu/%llu \033[90m|\033[0m %s \033[90m|\033[0m \033[36m%s\033[0m \033[90m|\033[0m %s%s",
            barBuf,
            pct,
            static_cast<unsigned long long>(files),
            static_cast<unsigned long long>(totalFiles_),
            dataBuf,
            tputStr,
            elapsedStr,
            (fails > 0) ? " \033[1;31m[!]\033[0m" : "");

        if (byteLen <= 0) return;

        // 10. Skip render if nothing changed — avoids redundant fflush.
        if (byteLen == prevByteLen &&
            std::memcmp(lineBuf, prevBuf, static_cast<std::size_t>(byteLen)) == 0) {
            return;
        }

        // 11. Write to stdout using ANSI clear-to-end-of-line (\r\033[K).
        std::fwrite("\r\033[K", 1, 4, stdout);
        std::fwrite(lineBuf, 1, static_cast<std::size_t>(byteLen), stdout);
        std::fflush(stdout);

        // 12. Update previous state.
        std::memcpy(prevBuf, lineBuf, static_cast<std::size_t>(byteLen) + 1);
        prevByteLen = byteLen;
    };

    // -----------------------------------------------------------------------
    // Main loop: render → sleep 500ms → repeat.
    // Predicate check ensures instant wakeup when stop() fires.
    // -----------------------------------------------------------------------
    while (true) {
        render();

        std::unique_lock<std::mutex> lock(mtx_);
        const bool stopped = cv_.wait_for(lock, std::chrono::milliseconds(500),
            [this]() noexcept { return !running_.load(std::memory_order_relaxed); });

        if (stopped) {
            lock.unlock();
            render(); // final pass — bar reaches 100%
            break;
        }
    }

    std::fputc('\n', stdout);
    std::fflush(stdout);
}
