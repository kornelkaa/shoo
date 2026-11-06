#!/bin/sh
# Builds shoo for Apple Silicon and Intel Macs (one universal file) and
# publishes it as a GitHub release, which install.sh downloads.
# Usage: scripts/release.sh 0.2.1   (from main, with everything committed)
# Downloads work for everyone only when the repo is public.
set -eu
cd "$(dirname "$0")/.."
VERSION="${1:?usage: scripts/release.sh VERSION (e.g. 0.2.1)}"
TAG="v$VERSION"
REPO="kornelkaa/shoo"
ASSET="shoo-macos.tar.gz"

[ "$(git branch --show-current)" = main ] || { echo "Release from main." >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "Commit your changes first." >&2; exit 1; }
go vet ./...
go test ./...
scripts/check-youtube-untouched.sh

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
for arch in arm64 amd64; do
  CGO_ENABLED=0 GOOS=darwin GOARCH="$arch" go build -trimpath \
    -ldflags "-s -w -X main.version=$VERSION" -o "$out/shoo-$arch" ./cmd/shoo
done
lipo -create -output "$out/shoo" "$out/shoo-arm64" "$out/shoo-amd64"
"$out/shoo" version
tar -czf "$out/$ASSET" -C "$out" shoo
(cd "$out" && shasum -a 256 "$ASSET" > "$ASSET.sha256")
cat "$out/$ASSET.sha256"

git tag -a "$TAG" -m "shoo $TAG"
git push origin "$TAG"
gh release create "$TAG" --repo "$REPO" --title "shoo $TAG" --generate-notes \
  "$out/$ASSET" "$out/$ASSET.sha256"
echo "Released $TAG. Install with:"
echo "  curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | sh"
