#!/bin/bash
# sign-dir.sh — recursively sign all files under a directory with ML-DSA-87,
# using a publisher identity from ~/.TPM/<DOMAIN>/.
#
# Usage: sign-dir.sh DOMAIN [DIR]
#
#   DOMAIN  publisher identity, e.g. `factsorlie.com` or
#           `factsorlie.com-Alice`.  Resolves to ~/.TPM/<DOMAIN>/,
#           which must contain private_key.pem (ML-DSA-87) and
#           index (the leaf cert index in the MTC log).  These are
#           established by bootstrap_leaf / bootstrap_ca.
#   DIR     directory to sign (default: current dir).
#
# Produces DIR/MANIFEST.sha256 (one SHA-256 per regular file under
# DIR, paths relative to DIR; MANIFEST.* and private_key.pem
# excluded; symlinks followed; `.git` pruned) and DIR/MANIFEST.sig
# (pure ML-DSA-87 signature over MANIFEST.sha256).  Verify with
# verify-dir.sh.
#
# Manifest header lines (all signed):
#   # publisher: <DOMAIN>
#   # publisher-cert-index: <N from ~/.TPM/<DOMAIN>/index>
#   # git-commit: <HEAD-hash>[-dirty]    (only if DIR is in a git repo)
#
# These let a verifier confirm which TPM identity signed and replay
# any forensic checks.  verify-dir.sh checks publisher == DOMAIN
# arg, recorded cert index against ~/.TPM/<DOMAIN>/index, and that
# git-commit (if recorded) exists in the local repo's object DB.

set -euo pipefail

RESPECT_GITIGNORE=0
POSITIONAL=()
while [ $# -gt 0 ]; do
    case "$1" in
        -g|--respect-gitignore) RESPECT_GITIGNORE=1; shift ;;
        -h|--help)
            echo "Usage: sign-dir.sh [-g|--respect-gitignore] DOMAIN [DIR]" >&2
            exit 0 ;;
        --) shift; while [ $# -gt 0 ]; do POSITIONAL+=("$1"); shift; done ;;
        -*) echo "sign-dir: unknown flag '$1'" >&2; exit 1 ;;
        *)  POSITIONAL+=("$1"); shift ;;
    esac
done
set -- "${POSITIONAL[@]}"

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "Usage: sign-dir.sh [-g|--respect-gitignore] DOMAIN [DIR]" >&2
    exit 1
fi

DOMAIN="$1"
DIR="${2:-.}"
DIR="$(cd "$DIR" && pwd)"

TPM_DIR="$HOME/.TPM/$DOMAIN"
PRIV="$TPM_DIR/private_key.pem"
INDEX_FILE="$TPM_DIR/index"

[ -d "$TPM_DIR"    ] || { echo "sign-dir: no TPM identity at $TPM_DIR" >&2; exit 1; }
[ -r "$PRIV"       ] || { echo "sign-dir: missing private key: $PRIV" >&2; exit 1; }
[ -r "$INDEX_FILE" ] || { echo "sign-dir: missing cert index: $INDEX_FILE" >&2; exit 1; }

CERT_INDEX="$(cat "$INDEX_FILE")"

GIT_COMMIT=""
if git -C "$DIR" rev-parse --verify HEAD >/dev/null 2>&1; then
    GIT_COMMIT="$(git -C "$DIR" rev-parse HEAD)"
    if ! git -C "$DIR" diff-index --quiet HEAD -- . 2>/dev/null; then
        GIT_COMMIT="${GIT_COMMIT}-dirty"
    fi
fi

cd "$DIR"

if [ "$RESPECT_GITIGNORE" = "1" ]; then
    if ! git -C "$DIR" rev-parse --git-dir >/dev/null 2>&1; then
        echo "sign-dir: --respect-gitignore set but $DIR is not in a git repo" >&2
        exit 1
    fi
    # tracked + untracked-but-not-ignored.  -z + read -d '' handles
    # paths with spaces / unusual chars; awk filter drops the same
    # special files the find branch hides.
    mapfile -d '' FILES_RAW < <(
        git -C "$DIR" ls-files -z --cached --others --exclude-standard
    )
    FILES=()
    for f in "${FILES_RAW[@]}"; do
        case "$f" in
            MANIFEST.sha256|MANIFEST.sig|private_key.pem) continue ;;
            */private_key.pem)                            continue ;;
        esac
        # ls-files lists tracked entries even if currently absent from
        # the worktree (e.g. partial checkout).  Skip those — sha256sum
        # would fail.
        [ -f "$f" ] || continue
        FILES+=("$f")
    done
    # Sort with the same locale-stable order as the find branch.
    mapfile -t FILES < <(printf '%s\n' "${FILES[@]}" | LC_ALL=C sort)
else
    mapfile -t FILES < <(
        find -L . -path ./.git -prune -o \
             -type f \
             ! -name MANIFEST.sha256 \
             ! -name MANIFEST.sig \
             ! -name private_key.pem \
             -printf '%P\n' | LC_ALL=C sort
    )
fi

if [ ${#FILES[@]} -eq 0 ]; then
    echo "sign-dir: no files to sign in $DIR" >&2
    exit 1
fi

{
    printf '# publisher: %s\n' "$DOMAIN"
    printf '# publisher-cert-index: %s\n' "$CERT_INDEX"
    [ -n "$GIT_COMMIT" ] && printf '# git-commit: %s\n' "$GIT_COMMIT"
    sha256sum -- "${FILES[@]}"
} > MANIFEST.sha256

openssl40 pkeyutl -sign -rawin \
    -inkey "$PRIV" \
    -in MANIFEST.sha256 \
    -out MANIFEST.sig

SRC_NOTE=""
[ "$RESPECT_GITIGNORE" = "1" ] && SRC_NOTE=" [respect-gitignore]"
echo "signed $DIR as $DOMAIN (cert index $CERT_INDEX, ${#FILES[@]} files)$SRC_NOTE"
