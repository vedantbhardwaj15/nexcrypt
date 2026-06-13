#ifndef PROCESS_MANAGEMENT-HPP
#define PROCESS_MANAGEMENT-HPP

#include "Task.hpp"
#include <queue>
#include <memory>

class ProcessManagement{
    public:
        ProcessManagement();
        bool submitToQueue(std::unique_ptr<Task> task);
        void executeTasks();
    private:
        std::queue<std::unique_ptr<Task>> taskQueue;
};

#endif