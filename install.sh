#!/bin/sh
set -e

# Orvpass Universal Multi-Platform Installer (macOS & Linux)
# Usage: curl -fsSL https://raw.githubusercontent.com/krtvysinghhhh/Orvpass/main/install.sh | bash

echo "⚡ Installing Orvpass CLI (Ultra-Fast Zero-Knowledge Secrets Manager)..."

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64|amd64) ARCH="x86_64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "❌ Unsupported architecture: $ARCH"; exit 1 ;;
esac

TAG="v5.5.0"
REPO="krtvysinghhhh/Orvpass"

# On macOS, check if Homebrew is available
if [ "$OS" = "darwin" ] && command -v brew >/dev/null 2>&1; then
  echo "🍺 Homebrew detected on macOS! Installing via official tap..."
  brew tap krtvysinghhhh/tap
  brew install orvpass
  echo ""
  echo "✨ Orvpass installed successfully via Homebrew!"
  echo "🚀 Run 'orvpass' to launch interactive TUI dashboard or 'orvpass --help' for CLI commands."
  exit 0
fi

if [ "$OS" = "darwin" ]; then
  FILE="orvpass-${TAG}-macos-${ARCH}.tar.gz"
elif [ "$OS" = "linux" ]; then
  FILE="orvpass-${TAG}-linux-${ARCH}.tar.gz"
else
  echo "❌ Unsupported operating system: $OS. For Windows, please run install.ps1 in PowerShell."
  exit 1
fi

URL="https://github.com/${REPO}/releases/download/${TAG}/${FILE}"
TMP_DIR="$(mktemp -d)"

echo "📥 Fetching binary for ${OS}-${ARCH} (${TAG})..."
if curl -fsSL "$URL" -o "${TMP_DIR}/${FILE}" 2>/dev/null; then
  tar -xzf "${TMP_DIR}/${FILE}" -C "${TMP_DIR}"
  BIN_SRC="${TMP_DIR}/orvpass"
else
  echo "📦 Release archive not found directly, compiling from source via cargo..."
  if command -v cargo >/dev/null 2>&1; then
    cargo install --git "https://github.com/${REPO}.git" orvpass-cli
    echo "✨ Orvpass built and installed successfully to $(which orvpass)!"
    rm -rf "$TMP_DIR"
    exit 0
  else
    echo "❌ Cargo not found. Please install Rust (https://rustup.rs) or install Homebrew."
    rm -rf "$TMP_DIR"
    exit 1
  fi
fi

INSTALL_DIR="/usr/local/bin"
if [ ! -w "$INSTALL_DIR" ]; then
  INSTALL_DIR="${HOME}/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi

cp "$BIN_SRC" "${INSTALL_DIR}/orvpass"
chmod +x "${INSTALL_DIR}/orvpass"
rm -rf "$TMP_DIR"

echo "✨ Orvpass installed successfully to ${INSTALL_DIR}/orvpass!"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo "⚠️  Note: Make sure $INSTALL_DIR is in your PATH (e.g. export PATH=\"$INSTALL_DIR:\$PATH\")" ;;
esac

echo "🚀 Run 'orvpass' to launch interactive TUI dashboard or 'orvpass --help' for CLI commands."
