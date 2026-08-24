#ifndef IO_HPP
#define IO_HPP

#include <filesystem>
#include <fstream>

class IO{
    public:
        IO(const std::filesystem::path &file_path); //no copy, read only
        ~IO();
        std::fstream getFileStream();

    private:
        std::fstream file_stream;
};

#endif
