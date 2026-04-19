#!/bin/sh
# register-ca.sh — one-command CA first-enrollment for postWolf.
#
# Orchestrates:
#   0. existing-identity guard (warn on active, announce on expired/revoked)
#   1. keygen (create_ca_cert.py) — skipped if keys already exist
#   2. prints DNS TXT record (ca_dns_txt.py)
#   3. interactive Proceed [Y/n/q] gate
#   4. DNS polling with in-place progress bar (5 min per cycle, repeatable)
#   5. bootstrap_ca
#
# Requires: create_ca_cert.py, ca_dns_txt.py, bootstrap_ca, revoke-key,
#           dig (dnsutils), python3.

set -eu

DOMAIN=""; SERVER=""; LABEL=""; ALGO="ML-DSA-87"
FORCE_KEYGEN=0; NO_PROMPT=0; DRY_RUN=0; MAKE_DEFAULT=0
RESOLVER="${RESOLVER:-8.8.8.8}"
POLL_ROUNDS=30        # each round is 10s → 5 min per cycle
POLL_INTERVAL=10

usage() {
    cat >&2 <<EOF
Usage: $0 --domain DOMAIN --server HOST:PORT [options]

Options:
  --domain DOMAIN     CA domain (required)
  --server H:P        DH bootstrap server (required; typically HOST:8445)
  --label LABEL       Optional TPM label; identity stored under
                      ~/.TPM/<domain>-<label>-ca/
  --algorithm ALG     Key algorithm (default: ML-DSA-87)
  --make-default      Atomically re-point ~/.TPM/default at this new
                      identity even if one already exists
  --force-keygen      Regenerate keypair even if ~/.mtc-ca-data/<dom>/
                      already has material
  --no-prompt         Non-interactive: accept prompt defaults and
                      treat DNS timeout as fatal
  --dry-run           Do everything except bootstrap_ca
  -h, --help          This help

Env:
  RESOLVER=8.8.8.8    Public DNS resolver used during poll

Orchestrates:
  0. checks ~/.TPM for an existing CA identity (active → warn)
  1. keygen (create_ca_cert.py --domain X --algorithm ALG)
  2. prints DNS TXT record (ca_dns_txt.py)
  3. waits for you to publish — Proceed [Y/n/q]?
  4. polls DNS for up to 5 min (with progress bar), repeatable
  5. invokes bootstrap_ca
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
    # $1 = prompt text, $2 = default (Y|n|q) when Enter pressed / non-tty
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

# is_index_revoked: GET /revoked/<idx> over TLS 8444 (public read,
# self-signed cert, no MQC identity needed).  Exits 0 if the server
# says revoked, 1 if not, 2 on network/parse error.
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

draw_bar() {
    # $1 = filled (0..POLL_ROUNDS), $2 = total, $3 = suffix text
    if [ "$NO_PROMPT" -eq 1 ] || [ ! -t 1 ]; then return 0; fi
    filled="$1"; total="$2"; suffix="$3"
    bar=""
    i=0
    while [ "$i" -lt "$total" ]; do
        if [ "$i" -lt "$filled" ]; then bar="${bar}#"; else bar="${bar}."; fi
        i=$((i + 1))
    done
    mm=$((filled * POLL_INTERVAL / 60))
    ss=$((filled * POLL_INTERVAL % 60))
    total_mm=$((total * POLL_INTERVAL / 60))
    total_ss=$((total * POLL_INTERVAL % 60))
    printf "\r  DNS propagation: [%s] %d:%02d / %d:%02d  %s    " \
        "$bar" "$mm" "$ss" "$total_mm" "$total_ss" "$suffix"
}

# --- 0. existing-identity guard ---
TPM_DIR="$HOME/.TPM/${DOMAIN}${LABEL:+-${LABEL}}-ca"
if [ -d "$TPM_DIR" ] \
   && [ -f "$TPM_DIR/certificate.json" ] \
   && [ -f "$TPM_DIR/index" ]; then
    cert_idx="$(cat "$TPM_DIR/index")"
    not_after="$(python3 -c "
import json,sys
d=json.load(open('$TPM_DIR/certificate.json'))
print(int(d['standalone_certificate']['tbs_entry']['not_after']))
" 2>/dev/null || echo 0)"
    now="$(date +%s)"

    if [ "$not_after" -lt "$now" ]; then
        echo "==> existing CA identity at $TPM_DIR is EXPIRED; re-enrollment is appropriate. Proceeding."
    elif is_index_revoked "$cert_idx"; then
        cat >&2 <<REVOKED

ERROR: existing CA identity at $TPM_DIR is REVOKED.

cert_index $cert_idx was revoked by the server operator.  A revoked
CA means the operator has decided this domain should not hold a CA
cert here.  Re-enrollment is **refused**.  The server (mtc_bootstrap.c)
enforces this policy too — even if you bypass this check, the
bootstrap will be rejected.

To resolve, contact the server operator by opening an issue at:

    https://github.com/cpsource/postWolf/issues

Include your domain ("$DOMAIN"), cert_index ($cert_idx), and why
you believe the revocation should be lifted.  Once the operator
lifts the revocation, re-run this command.

REVOKED
        exit 1
    else
        expires_str="$(date -u -d "@$not_after" 2>/dev/null || echo "$not_after")"
        cat >&2 <<WARN

WARNING: An active CA identity for $DOMAIN already exists:
    $TPM_DIR
    cert_index $cert_idx, not_after $expires_str

Re-registering creates a ghost log entry for the old key-pair
(server does not de-duplicate — see TODO #32).  Usually you want:
  - rotate keys:   check-renewal-cert --force ${DOMAIN}${LABEL:+-${LABEL}}-ca
  - replace fully: revoke-key --target-index $cert_idx ...  then re-run this

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
   && [ -f "$CA_DATA/ca_cert.pem" ] \
   && [ "$FORCE_KEYGEN" -eq 0 ]; then
    echo "==> reusing existing key material at $CA_DATA"
else
    echo "==> generating $ALGO keypair + X.509 CA cert for $DOMAIN"
    create_ca_cert.py --domain "$DOMAIN" --algorithm "$ALGO"
fi

# --- 2. extract TXT record ---
# ca_dns_txt.py emits:
#   _mtc-ca.<domain>.  IN TXT  "v=mtc-ca1; fp=sha256:<hex>"
TXT_LINE="$(ca_dns_txt.py "$CA_DATA/ca_cert.pem" \
             | awk -F'"' '/IN TXT/ { print $2; exit }')"
[ -n "$TXT_LINE" ] || {
    echo "ERROR: could not parse ca_dns_txt.py output" >&2; exit 1;
}
EXPECTED_FP="$(echo "$TXT_LINE" \
    | sed -n 's/.*fp=sha256:\([a-f0-9]*\).*/\1/p')"
[ -n "$EXPECTED_FP" ] || {
    echo "ERROR: no fingerprint in TXT record" >&2; exit 1;
}

cat <<BANNER

Publish this DNS TXT record at your DNS provider:

    _mtc-ca.$DOMAIN.  IN  TXT  "$TXT_LINE"

BANNER

# --- 3. publish-gate ---
ans="$(prompt_ynq "After publishing the record, proceed? [Y/n/q]" Y)"
case "$ans" in
    q) echo "aborting."; exit 1 ;;
    n) echo "==> skipping DNS poll; trying bootstrap_ca directly."
       SKIP_POLL=1 ;;
    *) SKIP_POLL=0 ;;
esac

# --- 4. DNS poll (unless skipped) ---
poll_dns_cycle() {
    i=0
    draw_bar 0 "$POLL_ROUNDS" "waiting ..."
    while [ "$i" -lt "$POLL_ROUNDS" ]; do
        i=$((i + 1))
        got="$(dig @"$RESOLVER" +short +time=3 +tries=1 TXT \
               "_mtc-ca.$DOMAIN" 2>/dev/null \
               | tr -d '"' | grep -F "fp=sha256:$EXPECTED_FP" || true)"
        if [ -n "$got" ]; then
            draw_bar "$POLL_ROUNDS" "$POLL_ROUNDS" "visible ✓"
            [ -t 1 ] && printf "\n"
            return 0
        fi
        draw_bar "$i" "$POLL_ROUNDS" "attempt $i/$POLL_ROUNDS"
        if [ "$NO_PROMPT" -eq 1 ] || [ ! -t 1 ]; then
            printf "  [%d/%d] TXT not visible; retry in %ds\n" \
                "$i" "$POLL_ROUNDS" "$POLL_INTERVAL"
        fi
        sleep "$POLL_INTERVAL"
    done
    [ -t 1 ] && printf "\n"
    return 1
}

if [ "$SKIP_POLL" -eq 0 ]; then
    echo "==> polling DNS via $RESOLVER (up to 5 min) ..."
    while ! poll_dns_cycle; do
        ans="$(prompt_ynq "Waited 5 min. Wait another 5? [Y/n/q]" q)"
        case "$ans" in
            Y) echo "==> polling another 5 min ..." ;;
            n) echo "==> skipping polling; trying bootstrap_ca directly."
               break ;;
            q|*) echo "aborting."; exit 1 ;;
        esac
    done
fi

# --- 5. bootstrap ---
if [ "$DRY_RUN" -eq 1 ]; then
    echo "==> dry-run: skipping bootstrap_ca"
    exit 0
fi

echo "==> running bootstrap_ca ..."
set -- bootstrap_ca --domain "$DOMAIN" --server "$SERVER"
[ -n "$LABEL" ] && set -- "$@" --label "$LABEL"
[ "$MAKE_DEFAULT" -eq 1 ] && set -- "$@" --make-default
"$@"

echo
echo "==> DONE. identity at $TPM_DIR"
if [ -L "$HOME/.TPM/default" ]; then
    echo "    ~/.TPM/default -> $(readlink "$HOME/.TPM/default")"
else
    echo "    (no ~/.TPM/default symlink — bootstrap_ca should have created one)"
fi
