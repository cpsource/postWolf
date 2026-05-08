#!/bin/bash
# sign-dir.sh — recursively sign all files under a directory with ML-DSA-87.
#
# Usage: sign-dir.sh [DIR]            (default: current dir)
#        FIPS_KEY_DIR=... sign-dir.sh [DIR]
#
# Produces DIR/MANIFEST.sha256 (one SHA-256 per regular file under DIR,
# paths relative to DIR; MANIFEST.* and private_key.pem excluded;
# symlinks are followed) and DIR/MANIFEST.sig (pure ML-DSA-87 signature
# over MANIFEST.sha256).  Verify with verify-dir.sh.
#
# When DIR is inside a git repo, the manifest is prefixed with a
# `# git-commit: <hash>[-dirty]` line.  The signature covers it.
# verify-dir.sh checks that the recorded hash exists as a commit
# object in the local repo (not necessarily HEAD), which catches
# manifests sourced from a different repo and outright fabricated
# commit IDs.  It deliberately does NOT compare to HEAD — natural
# workflows (commit-after-sign, verify against historical tags) leave
# the recorded commit somewhere in the repo's history but not at the
# tip, and we don't want to warn on those.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KEY_DIR="${FIPS_KEY_DIR:-$HERE/../../fips-keys}"
PRIV="$KEY_DIR/private_key.pem"

DIR="${1:-.}"
DIR="$(cd "$DIR" && pwd)"

[ -r "$PRIV" ] || { echo "sign-dir: missing private key: $PRIV" >&2; exit 1; }

GIT_COMMIT=""
if git -C "$DIR" rev-parse --verify HEAD >/dev/null 2>&1; then
    GIT_COMMIT="$(git -C "$DIR" rev-parse HEAD)"
    if ! git -C "$DIR" diff-index --quiet HEAD -- . 2>/dev/null; then
        GIT_COMMIT="${GIT_COMMIT}-dirty"
    fi
fi

cd "$DIR"

mapfile -t FILES < <(
    find -L . -path ./.git -prune -o \
         -type f \
         ! -name MANIFEST.sha256 \
         ! -name MANIFEST.sig \
         ! -name private_key.pem \
         -printf '%P\n' | LC_ALL=C sort
)

if [ ${#FILES[@]} -eq 0 ]; then
    echo "sign-dir: no files to sign in $DIR" >&2
    exit 1
fi

{
    [ -n "$GIT_COMMIT" ] && printf '# git-commit: %s\n' "$GIT_COMMIT"
    sha256sum -- "${FILES[@]}"
} > MANIFEST.sha256

openssl40 pkeyutl -sign -rawin \
    -inkey "$PRIV" \
    -in MANIFEST.sha256 \
    -out MANIFEST.sig

echo "signed $DIR (${#FILES[@]} files)"
