#!/usr/bin/env bash
#
# make-mqc-kit.sh — build a portable mqc-only install tarball from
# the current postWolf tree.
#
# Assumes the repo has already been built (./make-all.sh).  Stages
# just the mqc CLI plus libpostWolf.so runtime, packs as
# postWolf-mqc-kit-<version>.tar.gz.
#
# Use case: you want `mqc` on another Ubuntu box (e.g. a WSL2
# instance under Windows) without shipping the full CA/leaf kit.
#
set -euo pipefail

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SELF_DIR/.." && pwd)"
STAGE="$SELF_DIR/payload"
VERSION="$(git -C "$REPO_ROOT" describe --always --dirty 2>/dev/null || echo unversioned)"
TARBALL="$SELF_DIR/postWolf-mqc-kit-${VERSION}.tar.gz"

# --- 1. Sanity: required build artifacts must exist --------------------
required=(
    "mtc-keymaster/tools/c/mqc"
    "mtc-keymaster/README-mqc-cli.md"
)
missing=0
for f in "${required[@]}"; do
    if [[ ! -e "$REPO_ROOT/$f" ]]; then
        echo "Missing: $f" >&2
        missing=1
    fi
done

# libpostWolf.so may be in the in-tree build dir (src/.libs) OR in
# the system-wide install (/usr/local/lib) if `make install` has
# run since the last clean.  Prefer the in-tree copy, fall back to
# /usr/local/lib.
LIB_SRC=""
if [[ -e "$REPO_ROOT/src/.libs/libpostWolf.so" ]]; then
    LIB_SRC="$REPO_ROOT/src/.libs"
elif [[ -e "/usr/local/lib/libpostWolf.so" ]]; then
    LIB_SRC="/usr/local/lib"
else
    echo "Missing: libpostWolf.so (neither src/.libs nor /usr/local/lib)" >&2
    missing=1
fi

if (( missing )); then
    echo >&2
    echo "Build + install the full tree first:" >&2
    echo "    cd $REPO_ROOT && ./make-all.sh" >&2
    exit 1
fi

# --- 2. Source scripts next to this one --------------------------------
for src in install-mqc-kit.sh README-mqc.md; do
    if [[ ! -f "$SELF_DIR/$src" ]]; then
        echo "Missing: $SELF_DIR/$src" >&2
        exit 1
    fi
done

# --- 3. Stage the payload ---------------------------------------------
echo "Staging payload in $STAGE ..."
rm -rf "$STAGE"
mkdir -p "$STAGE/bin" "$STAGE/lib" "$STAGE/doc"

install -m 755 "$REPO_ROOT/mtc-keymaster/tools/c/mqc"   "$STAGE/bin/mqc"

# libpostWolf.so, libpostWolf.so.N (soname), libpostWolf.so.N.M.P (real).
# cp -a preserves the symlinks.
echo "Copying libpostWolf.so* from $LIB_SRC/"
cp -a "$LIB_SRC/"libpostWolf.so*  "$STAGE/lib/"

install -m 644 "$SELF_DIR/README-mqc.md"                          "$STAGE/doc/README.md"
install -m 644 "$REPO_ROOT/mtc-keymaster/README-mqc-cli.md"       "$STAGE/doc/README-mqc-cli.md"
install -m 755 "$SELF_DIR/install-mqc-kit.sh"  "$STAGE/install-mqc-kit.sh"
echo "$VERSION" > "$STAGE/VERSION"

# --- 4. Pack ----------------------------------------------------------
echo "Packing $TARBALL ..."
tar czf "$TARBALL" -C "$SELF_DIR" payload

echo
echo "Built: $TARBALL ($(du -h "$TARBALL" | cut -f1))"
echo
echo "Contents:"
tar tzf "$TARBALL"
