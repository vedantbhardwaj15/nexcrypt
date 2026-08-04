# Nexcrypt

Nexcrypt is a high-performance, multi-threaded command-line file encryption tool built with **C++17** and **libsodium**. It securely encrypts individual files and entire directory trees using **XChaCha20-Poly1305** streaming authenticated encryption, **Argon2id** password-based key derivation, and **BLAKE2b** per-file subkey derivation.

---

## Features

- **Multi-threaded Processing** – Configurable worker threads for high-throughput batch encryption and decryption.
- **Streaming Encryption** – Encrypts files in chunks, allowing efficient processing of very large files without loading them entirely into memory.
- **Dedicated Progress Thread** – Real-time progress reporting designed to avoid interfering with the encryption hot path.
- **Self-Describing File Format** – Stores the original chunk size inside the `NEXCRYPT2` file header, allowing automatic and correct decryption without requiring user input.
- **Header Validation** – Validates embedded chunk sizes (`4 KB` – `16 MB`) before allocation, preventing malformed or corrupted file headers from causing excessive memory allocation.
- **Safe Temporary Files** – Writes encrypted/decrypted output to temporary files first and performs an atomic rename only after successful completion, preventing partially written output files.
- **Authenticated Encryption** – Every encrypted file is cryptographically authenticated before being finalized.

---

## Cryptography

Nexcrypt uses modern authenticated encryption primitives provided by **libsodium**.

| Component | Algorithm |
|-----------|-----------|
| Encryption | XChaCha20-Poly1305 (`crypto_secretstream`) |
| Password KDF | Argon2id |
| Per-file Key Derivation | BLAKE2b |
| Authentication | Poly1305 Authentication Tags |

> **Important:** If the password is lost, encrypted data **cannot be recovered**.

---

## Download

Pre-built binaries are available on the **[Releases](https://github.com/vedantbhardwaj15/nexcrypt/releases)** page.

### Linux

- `nexcrypt-linux-x64.zip`

### Windows

- `nexcrypt-windows-x64.zip`

---

# Quick Start

## Linux

### 1. Extract

```bash
unzip nexcrypt-linux-x64.zip
cd nexcrypt-linux-x64
```

### 2. Make executable

```bash
chmod +x nexcrypt
```

### 3. Run

```bash
./nexcrypt
```

(Optional) Install system-wide:

```bash
sudo mv nexcrypt /usr/local/bin/
nexcrypt
```

---

## Windows

### 1. Extract

Right-click:

```
Extract All...
```

or use PowerShell:

```powershell
Expand-Archive -Path .\nexcrypt-windows-x64.zip -DestinationPath .\nexcrypt
cd .\nexcrypt
```

### 2. Run

```cmd
.\nexcrypt.exe
```

> **Note:** If dynamically linked, keep `libsodium.dll` in the same directory as `nexcrypt.exe`.

---

# Usage

Nexcrypt runs interactively.

```text
Enter file or directory path:
/path/to/my_folder

Enter action (ENCRYPT/DECRYPT):
ENCRYPT

Enter password:
********

Delete original files after encryption? (y/N): N

Enter number of parallel workers (default 4): 8

Enter chunk size in KB (default 256): 256

Scanning directory...
Found: 446 files (6.27 GB)

Encrypting...

[████████████████████] 100% | 446/446 | 6.27/6.27 GB | 185.4 MB/s | 34s

==================================================
PROCESSING COMPLETE
==================================================
Files processed : 446
Failures        : 0
Data processed  : 6.27 GB
Workers         : 8
Chunk size      : 256 KB
Time            : 34.2 s
Throughput      : 185.4 MB/s
==================================================
```

---

# Best Practices

## Linux

| Do | Don't |
|:---|:------|
| Run `chmod +x nexcrypt` before first use. | Don't run as `root` unless necessary. |
| Quote file paths containing spaces. | Don't interrupt Nexcrypt while it is actively processing files if original deletion is enabled. |
| Ensure sufficient free disk space (at least the size of the data being processed). | Don't manually modify or delete temporary `.tmp` files during execution. |

---

## Windows

| Do | Don't |
|:---|:------|
| Keep `libsodium.dll` beside `nexcrypt.exe` (dynamic builds). | Don't move `nexcrypt.exe` without its required DLLs. |
| Use Windows Terminal or PowerShell for proper UTF-8 progress bar rendering. | Don't manually rename `.nex` files before decrypting them. |
| If SmartScreen appears, click **More info → Run anyway** (unsigned binary). | Don't close the terminal until processing has completed. |

---

# Building From Source

## Requirements

- C++17 compiler (`g++`, `clang++`, or MSVC)
- CMake 3.10+
- libsodium

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y build-essential cmake libsodium-dev
```

### Fedora

```bash
sudo dnf install -y gcc-c++ cmake libsodium-devel
```

### macOS

```bash
brew install cmake libsodium
```

---

## Build

```bash
mkdir -p build
cd build

cmake .. -DCMAKE_BUILD_TYPE=Release

make -j$(nproc)
```

The executable will be generated in the `build` directory.

---

# License

No license has been specified yet.