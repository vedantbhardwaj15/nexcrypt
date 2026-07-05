nexcrypt
========

Small command-line file encryption tool using libsodium's secretstream API.

Prerequisites
-------------
- C++17 compiler (g++/clang)
- CMake >= 3.10
- libsodium development package

On Debian/Ubuntu:

```bash
sudo apt update
sudo apt install build-essential cmake libsodium-dev
```

Build
-----
```bash
mkdir -p build
cd build
cmake ..
cmake --build .
```

Run
---
Interactive:

```bash
./nexcrypt
# follow prompts: path, ENCRYPT/DECRYPT, password
```

Non-interactive example:

```bash
printf "/path/to/dir\nENCRYPT\nMyPassphrase\n" | ./nexcrypt
```

Behavior notes
--------------
- If given a directory path, the tool recursively processes regular files inside it (single-threaded by default).
- Encryption appends the `.nex` extension and skips files already ending with `.nex`.
- Decryption only processes `.nex` files and restores the original filename by removing the extension.

Files
-----
- See [CMakeLists.txt](CMakeLists.txt) for build configuration.
- See [main.cpp](main.cpp) for the CLI driver.

License
-------
No license specified.
