nexcrypt
========

nexcrypt is a small command-line file encryption tool built with C++17 and libsodium. It uses libsodium's secretstream API to encrypt and decrypt files and directories with a password-derived key.

Overview
--------

The project currently provides:
- a simple interactive CLI for encrypting and decrypting files or folders,
- recursive directory processing for regular files,
- safe temporary-file output handling during encryption/decryption,
- a CMake-based build setup for easy compilation.

Prerequisites
-------------

You will need:
- a C++17 compiler such as g++ or clang++,
- CMake 3.10 or newer,
- the libsodium development package.

On Debian/Ubuntu:

```bash
sudo apt update
sudo apt install build-essential cmake libsodium-dev
```

On Fedora/RHEL:

```bash
sudo dnf install gcc-c++ cmake libsodium-devel
```

Build
-----

From the project root:

```bash
mkdir -p build
cd build
cmake ..
cmake --build .
```

This will build:
- the main executable: ./nexcrypt

Usage
-----

Interactive mode:

```bash
./nexcrypt
```

You will be prompted for:
1. a file or directory path,
2. ENCRYPT or DECRYPT,
3. a password.

Example:

```bash
./nexcrypt
# Enter path: /path/to/file.txt
# Enter action: ENCRYPT
# Enter password: my-secret-password
```

Non-interactive example:

```bash
printf "/path/to/dir\nENCRYPT\nMyPassphrase\n" | ./nexcrypt
```

Behavior notes
--------------

- If the target is a directory, the tool recursively processes regular files inside it.
- Encryption appends the .nex extension and skips files that already end in .nex.
- Decryption only processes .nex files and restores the original filename by removing the extension.
- Temporary files are used during processing so that a failed run does not replace the final output immediately.
- The current implementation is single-threaded for file processing.

Project structure
-----------------

- main.cpp: CLI entry point and high-level workflow.
- src/app/encryptDecrypt/Cryption.cpp / Cryption.hpp: encryption and decryption logic.
- src/app/fileHandling/IO.cpp / IO.hpp: file I/O helpers.
- src/app/processes/ProcessManagement.cpp / ProcessManagement.hpp / Task.hpp: process/task management scaffolding.
- CMakeLists.txt: build configuration.

Development notes
-----------------

- The project is currently built around libsodium's secretstream API.
- The crypto implementation is intentionally defensive about file cleanup and error handling.
- Future work may include better CLI flags, automated tests, versioned file formats, and more polished release packaging.

License
-------

No license specified.
