#!/usr/bin/env bash
# MCP-Sentinel macOS & Linux Quick Installer
# Usage:
#   Standard (Default, with TUI Dashboard):
#     curl -fsSL https://raw.githubusercontent.com/joutvhu/mcp-sentinel/main/install.sh | sh
#   Headless (Micro-binary, no TUI):
#     curl -fsSL https://raw.githubusercontent.com/joutvhu/mcp-sentinel/main/install.sh | sh -s -- --headless
#     or: MCP_SENTINEL_HEADLESS=1 curl -fsSL https://raw.githubusercontent.com/joutvhu/mcp-sentinel/main/install.sh | sh

set -e

HEADLESS=0
for arg in "$@"; do
    case "$arg" in
        --headless|-headless)
            HEADLESS=1
            ;;
    esac
done

if [ "$MCP_SENTINEL_HEADLESS" = "1" ] || [ "$MCP_SENTINEL_HEADLESS" = "true" ]; then
    HEADLESS=1
fi

REPO="joutvhu/mcp-sentinel"
BIN_NAME="mcp-sentinel"
EDITION="Standard"
ASSET_PREFIX="mcp-sentinel"

if [ "$HEADLESS" -eq 1 ]; then
    EDITION="Headless"
    ASSET_PREFIX="mcp-sentinel-headless"
fi

printf "\033[36m🛡️ Installing mcp-sentinel for macOS / Linux (%s Edition)...\033[0m\n" "$EDITION"

# 1. Detect OS
OS_TYPE="$(uname -s)"
case "$OS_TYPE" in
    Darwin)
        OS="apple-darwin"
        ;;
    Linux)
        OS="unknown-linux-gnu"
        ;;
    *)
        printf "\033[31mError: Unsupported operating system: %s\033[0m\n" "$OS_TYPE"
        exit 1
        ;;
esac

# 2. Detect Architecture
ARCH_TYPE="$(uname -m)"
case "$ARCH_TYPE" in
    x86_64|amd64)
        ARCH="x86_64"
        ;;
    arm64|aarch64)
        ARCH="aarch64"
        ;;
    *)
        printf "\033[31mError: Unsupported architecture: %s\033[0m\n" "$ARCH_TYPE"
        exit 1
        ;;
esac

TARGET="${ARCH}-${OS}"
ASSET_NAME="${ASSET_PREFIX}-${TARGET}.tar.gz"

# 3. Determine Installation Directory
if [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
elif [ -n "$CARGO_HOME" ] && [ -d "$CARGO_HOME/bin" ]; then
    INSTALL_DIR="$CARGO_HOME/bin"
elif [ -d "$HOME/.cargo/bin" ]; then
    INSTALL_DIR="$HOME/.cargo/bin"
else
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
fi

# 4. Fetch latest version tag
printf "\033[33mFetching latest release information...\033[0m\n"
LATEST_TAG=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || echo "latest")

if [ "$LATEST_TAG" = "latest" ] || [ -z "$LATEST_TAG" ]; then
    DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${ASSET_NAME}"
else
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${ASSET_NAME}"
fi

# 5. Download and Extract
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

printf "\033[33mDownloading %s (%s)...\033[0m\n" "$ASSET_NAME" "$LATEST_TAG"
curl -sSL "$DOWNLOAD_URL" -o "$TMP_DIR/$ASSET_NAME"

# Verify SHA-256 checksum if .sha256 asset is available
if curl -sSL -f "${DOWNLOAD_URL}.sha256" -o "$TMP_DIR/$ASSET_NAME.sha256" 2>/dev/null; then
    printf "\033[33mVerifying SHA-256 checksum...\033[0m\n"
    (
        cd "$TMP_DIR"
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum -c "$ASSET_NAME.sha256" >/dev/null 2>&1 || { printf "\033[31mError: SHA-256 checksum mismatch!\033[0m\n"; exit 1; }
        elif command -v shasum >/dev/null 2>&1; then
            shasum -a 256 -c "$ASSET_NAME.sha256" >/dev/null 2>&1 || { printf "\033[31mError: SHA-256 checksum mismatch!\033[0m\n"; exit 1; }
        fi
    )
fi

printf "\033[33mExtracting to %s...\033[0m\n" "$INSTALL_DIR"
tar -xzf "$TMP_DIR/$ASSET_NAME" -C "$TMP_DIR"

# Stop any running mcp-sentinel processes before replacing binary
if pgrep -x "mcp-sentinel" >/dev/null 2>&1; then
    printf "\033[33mStopping running mcp-sentinel process(es) before upgrade...\033[0m\n"
    pkill -x "mcp-sentinel" 2>/dev/null || true
    sleep 0.3
fi

mv "$TMP_DIR/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"
chmod +x "$INSTALL_DIR/$BIN_NAME"

# 6. Check PATH
case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
        printf "\n\033[33mNotice: %s is not in your \$PATH.\033[0m\n" "$INSTALL_DIR"
        printf "Please add it to your shell profile (~/.bashrc, ~/.zshrc):\n"
        printf "  export PATH=\"%s:\$PATH\"\n" "$INSTALL_DIR"
        ;;
esac

printf "\n\033[32m✅ mcp-sentinel successfully installed to: %s/%s\033[0m\n" "$INSTALL_DIR" "$BIN_NAME"
"$INSTALL_DIR/$BIN_NAME" --version || true
