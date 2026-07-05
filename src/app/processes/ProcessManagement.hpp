#ifndef PROCESS_MANAGEMENT_HPP
#define PROCESS_MANAGEMENT_HPP

#include "Task.hpp"
#include <memory>
#include <queue>
#include <string>

class ProcessManagement{
    public:
        ProcessManagement();
        bool submitToQueue(std::unique_ptr<Task> task);
        void executeTasks(const std::string &password);
    private:
        std::queue<std::unique_ptr<Task>> taskQueue;
};

#endif