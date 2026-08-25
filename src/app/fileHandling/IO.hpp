#ifndef IO_HPP
#define IO_HPP

#include <filesystem>
#include <fstream>

#if defined(__unix__)
#include <fcntl.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

namespace IO {

/**
 * Advises the OS kernel/cache manager that the file will be read sequentially from start to finish.
 * - On Linux/POSIX: issues posix_fadvise with POSIX_FADV_SEQUENTIAL | POSIX_FADV_WILLNEED.
 * - On Windows: hints sequential prefetch cache strategy.
 * Safe no-op on filesystems or systems where readahead hints are unsupported.
 */
inline void hintSequentialRead(const std::filesystem::path &filePath) noexcept {
#if defined(__unix__)
    const int fd = ::open(filePath.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ::posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL | POSIX_FADV_WILLNEED);
        ::close(fd);
    }
#elif defined(_WIN32)
    HANDLE hFile = CreateFileW(filePath.c_str(),
                               GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr,
                               OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                               nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
    }
#endif
}

} // namespace IO

#endif // IO_HPP
