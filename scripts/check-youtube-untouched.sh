#!/bin/sh
# Fails if the YouTube ad-blocking code differs from the main branch.
# The YouTube code is frozen; other-site blocking lives in internal/sites.
set -e
cd "$(dirname "$0")/.."
YOUTUBE_CODE="internal/prune internal/certs internal/proxy"
if git diff --quiet main -- $YOUTUBE_CODE && [ -z "$(git ls-files --others --exclude-standard -- $YOUTUBE_CODE)" ]; then
  echo "OK: YouTube code is identical to main"
else
  echo "YouTube code differs from main:" >&2
  git diff --stat main -- $YOUTUBE_CODE >&2
  git ls-files --others --exclude-standard -- $YOUTUBE_CODE >&2
  exit 1
fi
