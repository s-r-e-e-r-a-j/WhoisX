#!/usr/bin/env bash

# WhoisX Installer Script
# Works on Linux and Termux (Android)
# Installs binary to system-wide PATH

SRC_FILE="whoisx.c"
BIN_FILE="whoisx"

# Detect environment
if [[ "$(uname -o 2>/dev/null)" == "Android" ]]; then
    ENV="termux"
    INSTALL_DIR="$PREFIX/bin"
else
    ENV="linux"
    INSTALL_DIR="/usr/local/bin"
fi

echo "[*] Detected environment: $ENV"
echo "[*] Install directory: $INSTALL_DIR"

# Ensure Linux user runs as root
if [[ "$ENV" == "linux" && "$EUID" -ne 0 ]]; then
    echo "[!] You must run this script as root on Linux."
    exit 1
fi

# Automatically install gcc on Linux if missing
if [[ "$ENV" == "linux" ]]; then
    if ! command -v gcc >/dev/null 2>&1; then
        echo "[*] gcc not found. Installing..."

        # Detect package manager
        if command -v apt >/dev/null 2>&1; then
            apt update -y
            apt install -y gcc
        elif command -v pacman >/dev/null 2>&1; then
            pacman -Sy --noconfirm gcc
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y gcc
        elif command -v yum >/dev/null 2>&1; then
            yum install -y gcc
        else
            echo "[!] No supported package manager found to install gcc."
            exit 1
        fi
    fi
fi

# Check source file
if [[ ! -f "$SRC_FILE" ]]; then
    echo "[!] Source file $SRC_FILE not found. Place it in the same directory."
    exit 1
fi

# Automatically install clang on termux if missing 
if [[ "$ENV" == "termux" ]]; then
     if ! command -v clang >/dev/null 2>&1; then
        echo "[*] clang not found. Installing..."
        pkg update -y
        pkg install -y clang
     fi
fi
        
# Build WhoisX
echo "[*] Building WhoisX..."
if [[ "$ENV" == "termux" ]]; then
    clang "$SRC_FILE" -o "$INSTALL_DIR/$BIN_FILE" -pthread
else
    gcc "$SRC_FILE" -o "$INSTALL_DIR/$BIN_FILE" -pthread
fi

# Check build success
if [[ -f "$INSTALL_DIR/$BIN_FILE" ]]; then
    chmod +x "$INSTALL_DIR/$BIN_FILE"
    echo "[+] Build successful! You can now run WhoisX from anywhere using the command: $BIN_FILE"
else
    echo "[!] Build failed. Check compiler output."
    exit 1
fi

echo "[*] Installation completed."
