#ifndef TASK_HPP
#define TASK_HPP

#include <filesystem>
#include <utility>

enum class Action {
    ENCRYPT,
    DECRYPT
};

struct Task {
    std::filesystem::path filePath;
    Action action;

    Task(Action act, std::filesystem::path path)
        : filePath(std::move(path)), action(act) {}
};

#endif