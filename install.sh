#!/bin/bash

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

# Check source file
if [[ ! -f "$SRC_FILE" ]]; then
    echo "[!] Source file $SRC_FILE not found. Place it in the same directory."
    exit 1
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
    echo "[+] Build successful! You can now run WhoisX from anywhere using the command:"
    echo "    $BIN_FILE"
else
    echo "[!] Build failed. Check compiler output."
    exit 1
fi

echo "[*] Installation completed."
