#ifndef IO_HPP
#define IO_HPP

#include <fstream>
#include <string>
#include <iostream>

class IO{
    public:
        IO(const std::string &file_path); //no copy, read only
        ~IO();
        std::fstream getFileStream();

    private:
        std::fstream file_stream;
};


#endif