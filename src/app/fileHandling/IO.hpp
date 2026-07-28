#ifndef IO_HPP
#define IO_HPP

#include <fstream>
#include <filesystem>
#include <iostream>

class IO{
    public:
        IO(const std::filesystem::path &file_path); //no copy, read only
        ~IO();
        std::fstream getFileStream();

    private:
        std::fstream file_stream;
};


#endif