#!/bin/sh
# register-leaf.sh — one-command leaf first-enrollment for postWolf.
#
# Two modes, chosen automatically:
#
#   Same-machine: a CA identity exists at ~/.TPM/*-ca/.  The wrapper
#   calls issue_leaf_nonce locally to mint a nonce, then bootstrap_leaf
#   to enroll — fully automated.
#
#   Cross-machine: no local CA.  The wrapper generates the leaf keypair,
#   prints the public_key.pem for the operator to send to their CA
#   operator out-of-band, prompts for the returned nonce, then runs
#   bootstrap_leaf.  Interactive; also accepts --nonce directly for
#   scripted use.
#
# Requires: create_leaf_keypair.py, bootstrap_leaf, issue_leaf_nonce
#           (only for same-machine mode), python3.

set -eu

DOMAIN=""; SERVER=""; LABEL=""; ALGO="ML-DSA-87"
NONCE=""; FORCE_KEYGEN=0; NO_PROMPT=0; DRY_RUN=0; MAKE_DEFAULT=0

usage() {
    cat >&2 <<EOF
Usage: $0 --domain DOMAIN --server HOST:PORT [options]

Options:
  --domain DOMAIN     Leaf domain (required, e.g. api.widget.corp)
  --server H:P        Server DH bootstrap endpoint (required; HOST:8445)
  --label LABEL       Optional TPM label; identity stored under
                      ~/.TPM/<domain>-<label>/
  --algorithm ALG     Key algorithm (default: ML-DSA-87)
  --nonce HEX         Pre-obtained enrollment nonce (64 hex chars).
                      Skips issue_leaf_nonce and the interactive prompt.
  --make-default      Atomically re-point ~/.TPM/default at this new
                      identity even if one already exists
  --force-keygen      Regenerate keypair even if ~/.mtc-ca-data/<dom>/
                      already has material
  --no-prompt         Non-interactive: fail if nonce cannot be obtained
                      automatically (no local CA, no --nonce, no stdin)
  --dry-run           Do everything except bootstrap_leaf
  -h, --help          This help

Flow:
  0. check ~/.TPM for an existing leaf identity (warn if active)
  1. keygen (create_leaf_keypair.py) — reused if keys exist
  2. obtain nonce (three-way fallback):
       a. --nonce HEX given on cmdline → use it
       b. local CA identity in ~/.TPM/*-ca → issue_leaf_nonce
       c. otherwise → print public key + instructions, prompt for paste
  3. invoke bootstrap_leaf
EOF
    exit 2
}

# --- arg parse ---
while [ "$#" -gt 0 ]; do
    case "$1" in
        --domain) DOMAIN="$2"; shift 2 ;;
        --server|-s) SERVER="$2"; shift 2 ;;
        --label) LABEL="$2"; shift 2 ;;
        --algorithm) ALGO="$2"; shift 2 ;;
        --nonce) NONCE="$2"; shift 2 ;;
        --make-default) MAKE_DEFAULT=1; shift ;;
        --force-keygen) FORCE_KEYGEN=1; shift ;;
        --no-prompt) NO_PROMPT=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage ;;
        *) echo "Error: unknown arg '$1'" >&2; usage ;;
    esac
done

[ -n "$DOMAIN" ] || { echo "Error: --domain is required" >&2; usage; }
[ -n "$SERVER" ] || { echo "Error: --server is required" >&2; usage; }

# --- helpers ---
prompt_ynq() {
    if [ "$NO_PROMPT" -eq 1 ] || [ ! -t 0 ]; then
        echo "$2"; return
    fi
    printf "%s " "$1" >&2
    IFS= read -r r
    [ -z "$r" ] && r="$2"
    case "$r" in
        Y|y|yes|YES) echo Y ;;
        N|n|no|NO) echo n ;;
        Q|q|quit|QUIT) echo q ;;
        *) echo "$2" ;;
    esac
}

has_local_ca() {
    for d in "$HOME"/.TPM/*-ca; do
        [ -d "$d" ] && return 0
    done
    return 1
}

# is_index_revoked: GET /revoked/<idx> over TLS 8444.  0=revoked,
# 1=not, 2=error.  See register-ca.sh for the same helper.
is_index_revoked() {
    local idx="$1"
    local host="${SERVER%:*}"
    python3 - "$host" "$idx" <<'PY' 2>/dev/null
import json, ssl, sys, urllib.request
host, idx = sys.argv[1], sys.argv[2]
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    r = urllib.request.urlopen(
        f"https://{host}:8444/revoked/{idx}", context=ctx, timeout=5)
    d = json.loads(r.read())
    sys.exit(0 if d.get("revoked") else 1)
except Exception:
    sys.exit(2)
PY
}

# --- 0. existing-identity guard ---
TPM_DIR="$HOME/.TPM/${DOMAIN}${LABEL:+-${LABEL}}"
if [ -d "$TPM_DIR" ] \
   && [ -f "$TPM_DIR/certificate.json" ] \
   && [ -f "$TPM_DIR/index" ]; then
    cert_idx="$(cat "$TPM_DIR/index")"
    not_after="$(python3 -c "
import json
d=json.load(open('$TPM_DIR/certificate.json'))
print(int(d['standalone_certificate']['tbs_entry']['not_after']))
" 2>/dev/null || echo 0)"
    now="$(date +%s)"

    if [ "$not_after" -lt "$now" ]; then
        echo "==> existing leaf identity at $TPM_DIR is EXPIRED; re-enrollment is appropriate. Proceeding."
    elif is_index_revoked "$cert_idx"; then
        cat >&2 <<REVOKED

ERROR: existing leaf identity at $TPM_DIR is REVOKED.

cert_index $cert_idx was revoked by your CA.  A revoked leaf means
the CA has decided this cert should not be in service.  Re-enrollment
is **refused**.  The server (mtc_bootstrap.c) enforces this policy
too — even if you bypass this check, the bootstrap will be rejected.

To resolve:
  - For routine key rotation: use check-renewal-cert (or
    /usr/local/sbin/setup-recert-crond.sh --start for auto-renewal).
    Renewal bypasses this check because it goes over MQC with the
    still-valid identity, not bootstrap.
  - If the revocation was in error: contact your CA operator.
    Lifting a revocation requires server-operator intervention via
    https://github.com/cpsource/postWolf/issues (MTC's append-only
    log has no built-in "unrevoke" primitive).

REVOKED
        exit 1
    else
        expires_str="$(date -u -d "@$not_after" 2>/dev/null || echo "$not_after")"
        cat >&2 <<WARN

WARNING: A leaf identity for $DOMAIN already exists:
    $TPM_DIR
    cert_index $cert_idx, not_after $expires_str

Re-enrolling creates a ghost log entry for the old key-pair
(server does not de-duplicate — see TODO #32).  To rotate keys on a
healthy leaf, use:

    check-renewal-cert --force ${DOMAIN}${LABEL:+-${LABEL}}

WARN
        ans="$(prompt_ynq "Proceed with a new registration anyway? [y/N/q]" n)"
        case "$ans" in
            Y) echo "==> proceeding — will create a second log entry." ;;
            *) echo "aborting."; exit 1 ;;
        esac
    fi
fi

# --- 1. keygen or reuse ---
CA_DATA="$HOME/.mtc-ca-data/$DOMAIN"
if [ -f "$CA_DATA/private_key.pem" ] \
   && [ -f "$CA_DATA/public_key.pem" ] \
   && [ "$FORCE_KEYGEN" -eq 0 ]; then
    echo "==> reusing existing key material at $CA_DATA"
else
    echo "==> generating $ALGO keypair for $DOMAIN"
    create_leaf_keypair.py --domain "$DOMAIN" --algorithm "$ALGO"
fi

# --- 2. obtain nonce ---
NONCE_FILE="$CA_DATA/nonce.txt"

write_nonce_file() {
    # $1 = 64-hex nonce
    mkdir -p "$CA_DATA"
    printf "%s\n" "$1" > "$NONCE_FILE"
    chmod 600 "$NONCE_FILE"
    echo "==> nonce saved to $NONCE_FILE"
}

validate_nonce_hex() {
    # $1 = candidate; returns 0 if 64 lowercase hex chars
    case "$1" in
        *[!0-9a-fA-F]*) return 1 ;;
    esac
    [ "${#1}" -eq 64 ] || return 1
    return 0
}

if [ -n "$NONCE" ]; then
    validate_nonce_hex "$NONCE" \
        || { echo "ERROR: --nonce must be 64 hex chars" >&2; exit 1; }
    write_nonce_file "$NONCE"
elif has_local_ca; then
    echo "==> same-machine mode: local CA identity found, issuing nonce"
    # issue_leaf_nonce speaks MQC (port 8446), while $SERVER is the DH
    # bootstrap endpoint (port 8445).  Derive the MQC endpoint from the
    # same host, defaulting to :8446.
    SERVER_HOST="${SERVER%:*}"
    MQC_SERVER="${SERVER_HOST}:8446"
    if ! issue_leaf_nonce --domain "$DOMAIN" \
                          --key-file "$CA_DATA/public_key.pem" \
                          --server  "$MQC_SERVER"; then
        echo "ERROR: issue_leaf_nonce failed against $MQC_SERVER" >&2
        exit 1
    fi
    # issue_leaf_nonce writes $NONCE_FILE itself; confirm.
    if [ ! -f "$NONCE_FILE" ]; then
        echo "ERROR: issue_leaf_nonce did not produce $NONCE_FILE" >&2
        exit 1
    fi
else
    cat >&2 <<EOT

==> cross-machine mode: no local CA identity.

Send this leaf public key to your CA operator:

  $CA_DATA/public_key.pem

Contents (copy-paste):
---8<---
EOT
    cat "$CA_DATA/public_key.pem" >&2
    cat >&2 <<'EOT'
--->8---

On their machine, they should run:

  issue_leaf_nonce --domain "<this-domain>" --key-file <your-public-key>

They will reply with a 64-hex-char nonce.  Paste it here:
EOT

    if [ "$NO_PROMPT" -eq 1 ] || [ ! -t 0 ]; then
        cat >&2 <<'EOT'

ERROR: no --nonce given, no local CA, and stdin is not a tty.
Re-run interactively, or pass --nonce <hex> once you have it.
EOT
        exit 1
    fi

    printf "Nonce: " >&2
    IFS= read -r NONCE
    NONCE="$(printf "%s" "$NONCE" | tr -d '[:space:]')"
    validate_nonce_hex "$NONCE" \
        || { echo "ERROR: nonce must be 64 hex chars" >&2; exit 1; }
    write_nonce_file "$NONCE"
fi

# --- 3. bootstrap ---
if [ "$DRY_RUN" -eq 1 ]; then
    echo "==> dry-run: skipping bootstrap_leaf"
    exit 0
fi

echo "==> running bootstrap_leaf ..."
set -- bootstrap_leaf --domain "$DOMAIN" --server "$SERVER"
[ -n "$LABEL" ] && set -- "$@" --label "$LABEL"
[ "$MAKE_DEFAULT" -eq 1 ] && set -- "$@" --make-default
"$@"

echo
echo "==> DONE. identity at $TPM_DIR"
if [ -L "$HOME/.TPM/default" ]; then
    echo "    ~/.TPM/default -> $(readlink "$HOME/.TPM/default")"
fi
