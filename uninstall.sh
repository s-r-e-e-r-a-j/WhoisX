#!/bin/bash

# WhoisX Uninstaller Script
# Works on Linux and Termux (Android)

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
echo "[*] Target binary: $INSTALL_DIR/$BIN_FILE"

# Ensure Linux user runs as root
if [[ "$ENV" == "linux" && "$EUID" -ne 0 ]]; then
    echo "[!] You must run this script as root on Linux."
    exit 1
fi

# Remove binary
if [[ -f "$INSTALL_DIR/$BIN_FILE" ]]; then
    rm -f "$INSTALL_DIR/$BIN_FILE"
    echo "[+] WhoisX has been removed from $INSTALL_DIR"
else
    echo "[!] WhoisX not found in $INSTALL_DIR"
fi

echo "[*] Uninstallation completed."
