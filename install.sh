#!/bin/sh
# Installs shoo, then starts `shoo setup`.
#
#   curl -fsSL https://raw.githubusercontent.com/kornelkaa/shoo/main/install.sh | sh
#
# It downloads the latest release from GitHub, checks its SHA-256 checksum,
# puts the `shoo` command in /usr/local/bin, owned by root (asks for your
# password), and runs `shoo setup`, which asks a few questions.
# Run the same command again to update.
set -eu

REPO="kornelkaa/shoo"
BASE_URL="${SHOO_BASE_URL:-https://github.com/$REPO/releases/latest/download}"
BIN_DIR="${SHOO_BIN_DIR:-/usr/local/bin}"

say() { printf '%s\n' "$*"; }
fail() { printf 'shoo install: %s\n' "$*" >&2; exit 1; }

case "$(uname -s)" in
  Darwin) ASSET="shoo-macos.tar.gz" ;;
  Linux)
    case "$(uname -m)" in
      x86_64 | amd64) ASSET="shoo-linux-amd64.tar.gz" ;;
      aarch64 | arm64) ASSET="shoo-linux-arm64.tar.gz" ;;
      *) fail "shoo isn't built for this processor ($(uname -m))." ;;
    esac
    ;;
  *) fail "shoo runs on macOS and Linux." ;;
esac
command -v curl >/dev/null || fail "curl is needed."

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading shoo..."
curl -fsSL "$BASE_URL/$ASSET" -o "$tmp/$ASSET" || fail "download failed: $BASE_URL/$ASSET"
curl -fsSL "$BASE_URL/$ASSET.sha256" -o "$tmp/$ASSET.sha256" || fail "checksum download failed"

want=$(awk '{print $1}' "$tmp/$ASSET.sha256")
if command -v shasum >/dev/null; then
  got=$(shasum -a 256 "$tmp/$ASSET" | awk '{print $1}')
else
  got=$(sha256sum "$tmp/$ASSET" | awk '{print $1}')
fi
[ -n "$want" ] && [ "$want" = "$got" ] || fail "checksum mismatch (expected $want, got $got); not installing."

tar -xzf "$tmp/$ASSET" -C "$tmp"
[ -f "$tmp/shoo" ] || fail "the download doesn't contain shoo."
chmod 755 "$tmp/shoo"
"$tmp/shoo" version >/dev/null || fail "the downloaded shoo doesn't run on this computer."

# shoo setup runs this file with sudo, so it belongs to root: nothing running
# as you can swap it for something else before then.
say "Installing to $BIN_DIR/shoo (needs your password)..."
sudo mkdir -p "$BIN_DIR"
sudo install -o root -g 0 -m 755 "$tmp/shoo" "$BIN_DIR/shoo"
say "Installed $("$BIN_DIR/shoo" version)."

if [ "${SHOO_NO_SETUP:-}" = 1 ]; then
  exit 0
fi

if [ "$(uname -s)" = Linux ] && ! command -v certutil >/dev/null; then
  say ""
  say "Note: Chrome and Firefox need certutil to trust shoo's certificate. Install it first:"
  say "  sudo apt install libnss3-tools   (Debian, Ubuntu)"
  say "  sudo dnf install nss-tools       (Fedora)"
  say "  sudo pacman -S nss               (Arch)"
fi

# With `curl | sh` this script's input is the download, not the keyboard:
# give setup the terminal so its questions work.
say ""
if [ -r /dev/tty ] && (: </dev/tty) 2>/dev/null; then
  "$BIN_DIR/shoo" setup </dev/tty
else
  say "No Terminal to ask questions in: run \`shoo setup\` to finish."
fi
