#!/bin/bash
# restore.sh — decrypt and restore the postWolf server-configuration-data
# artifacts onto a fresh machine.
#
# Two artifacts get restored, in this order:
#
#   1. env.enc.json            -> ~/.env
#   2. auth-bundle.tar.enc.json -> tar -xf - -C ~/
#                                  (drops .claude/.credentials.json,
#                                   .config/gh/{config,hosts}.yml,
#                                   .ssh/*, .gnupg/*)
#
# Both blobs were sealed with mqc (AES-256-GCM, scrypt KDF) using the
# MQC_MASTER_PASSWORD that was in ~/.env at backup time.  Since ~/.env
# doesn't exist yet on a fresh machine, the password has to be supplied
# out-of-band on the first run.
#
# Usage:
#   restore.sh                          # prompt for password
#   restore.sh -p 'my-secret-password'  # password on the cmd line (NOT for shells with history)
#   restore.sh --env-only               # only restore ~/.env
#   restore.sh --auth-only              # only restore the auth tar
#   restore.sh -n                       # dry-run; show what would be done
#   restore.sh -f                       # don't prompt before overwriting
#
# Prerequisites on the fresh machine:
#   - mqc binary on PATH (postWolf install: make -f Makefile.tools install)
#   - tar (every distro)
#   - bash 4+

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_BLOB="$SCRIPT_DIR/env.enc.json"
AUTH_BLOB="$SCRIPT_DIR/auth-bundle.tar.enc.json"

PASSWORD=""
DO_ENV=1
DO_AUTH=1
DRY_RUN=0
FORCE=0

usage() {
    sed -n '2,32p' "$0" | sed 's|^# \{0,1\}||'
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        -p|--password)  PASSWORD="$2"; shift 2 ;;
        --env-only)     DO_AUTH=0; shift ;;
        --auth-only)    DO_ENV=0;  shift ;;
        -n|--dry-run)   DRY_RUN=1; shift ;;
        -f|--force)     FORCE=1;   shift ;;
        -h|--help)      usage ;;
        *) echo "restore: unknown arg '$1'" >&2; usage ;;
    esac
done

# --- Prerequisites -----------------------------------------------------

command -v mqc >/dev/null 2>&1 || {
    echo "restore: mqc not on PATH; install postWolf tools first" >&2
    exit 1
}

if [ "$DO_ENV" = "1" ] && [ ! -r "$ENV_BLOB" ]; then
    echo "restore: $ENV_BLOB not readable" >&2
    exit 1
fi
if [ "$DO_AUTH" = "1" ] && [ ! -r "$AUTH_BLOB" ]; then
    echo "restore: $AUTH_BLOB not readable" >&2
    exit 1
fi

# --- Password ---------------------------------------------------------

if [ -z "$PASSWORD" ]; then
    if [ -t 0 ]; then
        printf 'mqc password: ' >&2
        IFS= read -r -s PASSWORD
        echo >&2
    else
        echo "restore: no password supplied and stdin isn't a tty" >&2
        exit 1
    fi
fi
[ -z "$PASSWORD" ] && { echo "restore: empty password" >&2; exit 1; }

# --- Helpers ----------------------------------------------------------

confirm() {
    [ "$FORCE" = "1" ] && return 0
    [ "$DRY_RUN" = "1" ] && return 0
    printf '%s [y/N] ' "$1" >&2
    read -r ans
    case "$ans" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

run() {
    if [ "$DRY_RUN" = "1" ]; then
        echo "[dry-run] $*" >&2
    else
        eval "$@"
    fi
}

# --- 1. env.enc.json -> ~/.env ----------------------------------------

if [ "$DO_ENV" = "1" ]; then
    target="$HOME/.env"
    if [ -e "$target" ]; then
        if ! confirm "$target exists; overwrite?"; then
            echo "restore: skipping env (already present)" >&2
            DO_ENV=0
        fi
    fi
    if [ "$DO_ENV" = "1" ]; then
        echo "[env] decrypting $ENV_BLOB -> $target" >&2
        if [ "$DRY_RUN" = "1" ]; then
            echo "[dry-run] mqc --decode --password '<elided>' --file $ENV_BLOB --out $target" >&2
        else
            mqc --decode --password "$PASSWORD" --file "$ENV_BLOB" --out "$target"
            chmod 0640 "$target"
        fi
    fi
fi

# --- 2. auth-bundle.tar.enc.json -> tar -xf - -C ~/ -------------------

if [ "$DO_AUTH" = "1" ]; then
    # Show what's in the tar so the operator knows what's about to land.
    # Read-only — runs in dry-run too, since the operator wants to see
    # the manifest before deciding.
    echo "[auth] tar manifest preview:" >&2
    mqc --decode --password "$PASSWORD" --file "$AUTH_BLOB" \
        | tar -tf - 2>/dev/null | sed 's/^/  /' >&2 || {
        echo "restore: failed to list tar manifest (wrong password?)" >&2
        exit 1
    }

    if ! confirm "[auth] extract into $HOME/ ? existing files will be overwritten"; then
        echo "restore: skipping auth bundle" >&2
    else
        echo "[auth] decrypting $AUTH_BLOB -> tar -xpf - -C $HOME" >&2
        if [ "$DRY_RUN" = "1" ]; then
            echo "[dry-run] mqc --decode --password '<elided>' --file $AUTH_BLOB | tar -xpf - -C $HOME" >&2
        else
            # -p preserves file modes (matters for .ssh keys at 0600).
            mqc --decode --password "$PASSWORD" --file "$AUTH_BLOB" \
                | tar -xpf - -C "$HOME"
        fi
    fi
fi

echo "restore: done." >&2
