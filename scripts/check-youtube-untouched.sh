#!/bin/sh
# Fails if the YouTube ad-blocking code differs from the main branch.
# The YouTube code is frozen; other-site blocking lives in internal/sites and
# YouTube add-ons wrap it from outside (internal/ytskip).
# The project was renamed from ytblock to shoo; that rename is the only
# difference allowed, so "ytblock" in main is read as "shoo".
set -e
cd "$(dirname "$0")/.."
YOUTUBE_CODE="internal/prune internal/certs internal/proxy"

bad=0
for f in $(git ls-tree -r --name-only main -- $YOUTUBE_CODE); do
  if [ ! -f "$f" ]; then
    echo "missing: $f" >&2; bad=1; continue
  fi
  if ! git show "main:$f" | sed 's/ytblock/shoo/g' | cmp -s - "$f"; then
    echo "changed: $f" >&2
    git show "main:$f" | sed 's/ytblock/shoo/g' | diff -u --label "main:$f" - "$f" >&2 || true
    bad=1
  fi
done
for f in $(git ls-files --others --exclude-standard -- $YOUTUBE_CODE) $(git diff --name-only --diff-filter=A main -- $YOUTUBE_CODE); do
  echo "new file: $f" >&2; bad=1
done

if [ "$bad" = 0 ]; then
  echo "OK: YouTube code is identical to main"
else
  echo "YouTube code differs from main" >&2
  exit 1
fi
