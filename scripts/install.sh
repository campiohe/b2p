#!/usr/bin/env bash
# Install the latest b2p release binary.
#
#   curl -fsSL https://raw.githubusercontent.com/campiohe/b2p/main/scripts/install.sh | bash
#
# Override the install location with B2P_INSTALL_DIR (default: ~/.local/bin).
set -euo pipefail

REPO="campiohe/b2p"
INSTALL_DIR="${B2P_INSTALL_DIR:-$HOME/.local/bin}"

os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
  Linux)
    case "$arch" in
      x86_64|amd64) asset="b2p-linux-x86_64.tar.gz" ;;
      *) echo "No prebuilt Linux binary for '$arch' (only x86_64). Build from source: cargo install --git https://github.com/$REPO" >&2; exit 1 ;;
    esac ;;
  Darwin)
    case "$arch" in
      arm64|aarch64) asset="b2p-macos-arm64.tar.gz" ;;
      *) echo "No prebuilt macOS binary for '$arch' (only Apple Silicon). Build from source: cargo install --git https://github.com/$REPO" >&2; exit 1 ;;
    esac ;;
  *) echo "Unsupported OS: '$os'. On Windows, download the .zip from the releases page." >&2; exit 1 ;;
esac

url="https://github.com/$REPO/releases/latest/download/$asset"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading $asset ..."
if ! curl -fsSL "$url" -o "$tmp/$asset"; then
  echo "Download failed. Is there a published release yet? See https://github.com/$REPO/releases" >&2
  exit 1
fi

echo "Extracting ..."
tar -xzf "$tmp/$asset" -C "$tmp"

mkdir -p "$INSTALL_DIR"
install -m 0755 "$tmp/b2p" "$INSTALL_DIR/b2p"
echo "Installed b2p -> $INSTALL_DIR/b2p"
if ver="$("$INSTALL_DIR/b2p" --version 2>/dev/null)"; then
  echo "$ver"
fi

case ":$PATH:" in
  *":$INSTALL_DIR:"*)
    echo "Ready. Run: b2p --help" ;;
  *)
    echo
    echo "NOTE: $INSTALL_DIR is not on your PATH. Add it, then reopen your shell:"
    echo "  echo 'export PATH=\"$INSTALL_DIR:\$PATH\"' >> ~/.bashrc" ;;
esac
