#ifndef TASK_HPP
#define TASK_HPP

#include <cstdint>
#include <filesystem>
#include <string>
#include <utility>

enum class Action {
    ENCRYPT,
    DECRYPT
};

inline std::string safePathString(const std::filesystem::path &p) {
    try {
        return p.string();
    } catch (...) {
        try {
            const auto u8 = p.u8string();
            return std::string(reinterpret_cast<const char *>(u8.data()), u8.size()); // pointer to the utf 8 bytes and treat them as read only char bytes.
        } catch (...) {
            return "<unprintable path>";
        }
    }
}

struct Task {
    std::filesystem::path filePath;
    Action                action;
    std::uint64_t         fileSize{0}; // pre-computed on the main thread; workers never read this

    Task(Action act, std::filesystem::path path, std::uint64_t size = 0)
        : filePath(std::move(path)), action(act), fileSize(size) {}
};

#endif