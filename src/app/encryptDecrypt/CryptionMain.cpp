#include <iostream>
#include <string>

#include "Cryption.hpp"

int main(int argc, char* argv[]){
    if(argc != 5){
        std::cerr << "Usage: ./cryption <ENCRYPT|DECRYPT> <input_path> <output_path> <password>" << std::endl;
        return 1;
    }

    const std::string action = argv[1];
    const std::string inputPath = argv[2];
    const std::string outputPath = argv[3];
    const std::string password = argv[4];

    if(action == "ENCRYPT"){
        return encryptFile(inputPath, outputPath, password) ? 0 : 1;
    }

    if(action == "DECRYPT"){
        return decryptFile(inputPath, outputPath, password) ? 0 : 1;
    }

    std::cerr << "Invalid action. Use ENCRYPT or DECRYPT." << std::endl;
    return 1;
}
