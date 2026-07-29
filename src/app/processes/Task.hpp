#ifndef TASK_HPP
#define TASK_HPP

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
            return std::string(reinterpret_cast<const char *>(u8.data()), u8.size());
        } catch (...) {
            return "<unprintable path>";
        }
    }
}

struct Task {
    std::filesystem::path filePath;
    Action action;

    Task(Action act, std::filesystem::path path)
        : filePath(std::move(path)), action(act) {}
};

#endif