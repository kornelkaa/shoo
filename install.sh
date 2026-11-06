#!/bin/sh
# Installs shoo, then starts `shoo setup`.
#
#   curl -fsSL https://raw.githubusercontent.com/kornelkaa/shoo/main/install.sh | sh
#
# It downloads the latest release from GitHub, checks its SHA-256 checksum,
# puts the `shoo` command in /usr/local/bin (asks for your password if that
# folder needs it), and runs `shoo setup`, which asks a few questions.
# Run the same command again to update.
set -eu

REPO="kornelkaa/shoo"
BASE_URL="${SHOO_BASE_URL:-https://github.com/$REPO/releases/latest/download}"
BIN_DIR="${SHOO_BIN_DIR:-/usr/local/bin}"
ASSET="shoo-macos.tar.gz"

say() { printf '%s\n' "$*"; }
fail() { printf 'shoo install: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = Darwin ] || fail "shoo only runs on macOS."
command -v curl >/dev/null || fail "curl is needed."

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading shoo..."
curl -fsSL "$BASE_URL/$ASSET" -o "$tmp/$ASSET" || fail "download failed: $BASE_URL/$ASSET"
curl -fsSL "$BASE_URL/$ASSET.sha256" -o "$tmp/$ASSET.sha256" || fail "checksum download failed"

want=$(awk '{print $1}' "$tmp/$ASSET.sha256")
got=$(shasum -a 256 "$tmp/$ASSET" | awk '{print $1}')
[ -n "$want" ] && [ "$want" = "$got" ] || fail "checksum mismatch (expected $want, got $got); not installing."

tar -xzf "$tmp/$ASSET" -C "$tmp"
[ -f "$tmp/shoo" ] || fail "the download doesn't contain shoo."
chmod 755 "$tmp/shoo"
"$tmp/shoo" version >/dev/null || fail "the downloaded shoo doesn't run on this Mac."

say "Installing to $BIN_DIR/shoo..."
if mkdir -p "$BIN_DIR" 2>/dev/null && [ -w "$BIN_DIR" ]; then
  mv -f "$tmp/shoo" "$BIN_DIR/shoo"
else
  say "(needs your password to write to $BIN_DIR)"
  sudo mkdir -p "$BIN_DIR"
  sudo mv -f "$tmp/shoo" "$BIN_DIR/shoo"
fi
say "Installed $("$BIN_DIR/shoo" version)."

if [ "${SHOO_NO_SETUP:-}" = 1 ]; then
  exit 0
fi

# With `curl | sh` this script's input is the download, not the keyboard:
# give setup the Terminal so its questions work.
say ""
if [ -r /dev/tty ] && (: </dev/tty) 2>/dev/null; then
  "$BIN_DIR/shoo" setup </dev/tty
else
  say "No Terminal to ask questions in: run \`shoo setup\` to finish."
fi
