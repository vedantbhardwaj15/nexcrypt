#ifndef TASK_HPP
#define TASK_HPP

#include <string>
#include <utility>

enum class Action {
    ENCRYPT,
    DECRYPT
};

struct Task {
    std::string filePath;
    Action action;

    Task(Action act, std::string path)
        : filePath(std::move(path)), action(act) {}
};

#endif