#include "ProcessManagement.hpp"

#include "../encryptDecrypt/Cryption.hpp"

#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

ProcessManagement::ProcessManagement(){};

bool ProcessManagement::submitToQueue(std::unique_ptr<Task> task){
    taskQueue.push(std::move(task));
    return true;
}

void ProcessManagement::executeTasks(const std::string &password){
    while(!taskQueue.empty()){
        std::unique_ptr<Task> taskToExecute = std::move(taskQueue.front());
        taskQueue.pop();
        const fs::path inputPath(taskToExecute->filePath);
        fs::path outputPath;
        if (taskToExecute->action == Action::ENCRYPT) {
            outputPath = fs::path(inputPath.string() + ".nex");
        } else {
            outputPath = inputPath;
            outputPath.replace_extension("");
        }

        std::cout << "Executing task: " << inputPath << std::endl;
        if (taskToExecute->action == Action::ENCRYPT) {
            encryptFile(inputPath.string(), outputPath.string(), password);
        } else {
            decryptFile(inputPath.string(), outputPath.string(), password);
        }
    }
}
