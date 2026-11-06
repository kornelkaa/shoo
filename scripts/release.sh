#!/bin/sh
# Publish a release and update the Homebrew formula's url and sha256.
# Usage: scripts/release.sh 0.1.0
# Needs a public repo (Homebrew can't download from a private one).
set -eu
cd "$(dirname "$0")/.."
VERSION="${1:?usage: scripts/release.sh VERSION (e.g. 0.1.0)}"
TAG="v$VERSION"
REPO="kornelkaa/shoo"
FORMULA="packaging/homebrew/shoo.rb"

[ "$(git branch --show-current)" = main ] || { echo "Release from main." >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "Commit your changes first." >&2; exit 1; }
go test ./...

git tag -a "$TAG" -m "shoo $TAG"
git push origin "$TAG"
gh release create "$TAG" --repo "$REPO" --title "shoo $TAG" --generate-notes

URL="https://github.com/$REPO/archive/refs/tags/$TAG.tar.gz"
SHA=$(curl -fsSL "$URL" | shasum -a 256 | cut -d' ' -f1)
sed -i '' -e "s|^  url \".*\"|  url \"$URL\"|" -e "s|^  sha256 \".*\"|  sha256 \"$SHA\"|" "$FORMULA"

echo "Updated $FORMULA:"
grep -E '^  (url|sha256) ' "$FORMULA"
echo
echo "Next: commit this change, then copy $FORMULA to Formula/shoo.rb"
echo "in the kornelkaa/homebrew-tap repo and push it."
