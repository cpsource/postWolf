# Leaf Registration

How to enroll a leaf identity against an already-registered MTC CA.
The end state: your leaf identity is in `~/.TPM/<domain>/`, the
server has your enrollment in its Merkle log, and the CA has issued
a one-shot nonce tying your public key to the new cert.

---

## Overview

Leaf enrollment is a two-party protocol:

1. **You** generate an ML-DSA-87 keypair and send the public key to
   the CA operator (or, in same-machine mode, to yourself).
2. **The CA operator** runs `issue_leaf_nonce` over MQC (port 8446)
   which asks the server for a 64-hex-char single-use nonce bound to
   `(domain, public-key-fingerprint, ca_cert_index)` with a 15-minute
   TTL.
3. **You** use that nonce during a DH bootstrap on port 8445. The
   server verifies the nonce matches the key you submitted, then mints
   an MTC `standalone_certificate` for `<domain>` at a new log index.

The nonce is what makes this safe: it binds a specific key to a
specific domain, pre-authorized by a CA that has authority for the
parent domain. No nonce = no enrollment.

---

## Fast path (recommended)

After installing `kit-leaf` (or `kit-CA`), one command walks you
through the whole thing:

```
register-leaf.sh --domain api.widget-corp.example \
                 --server ca.widget-corp.example:8445
```

The wrapper picks one of two modes automatically:

### Same-machine mode

Triggered when `~/.TPM/*-ca/` exists on the box (typical on a CA box
that's also hosting a service). Fully non-interactive:

```
==> generating ML-DSA-87 keypair for api.widget-corp.example
... [create_leaf_keypair.py output] ...
==> same-machine mode: local CA identity found, issuing nonce
... [issue_leaf_nonce MQC handshake + response] ...
==> running bootstrap_leaf ...
... [DH handshake, enrollment, MTC cert response] ...

==> DONE. identity at /home/ubuntu/.TPM/api.widget-corp.example
    ~/.TPM/default -> api.widget-corp.example
```

### Cross-machine mode

Triggered when no CA identity is present. Interactive:

```
==> generating ML-DSA-87 keypair for api.widget-corp.example
...

==> cross-machine mode: no local CA identity.

Send this leaf public key to your CA operator:

  /home/ubuntu/.mtc-ca-data/api.widget-corp.example/public_key.pem

Contents (copy-paste):
---8<---
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
--->8---

On their machine, they should run:

  issue_leaf_nonce --domain "<this-domain>" --key-file <your-public-key>

They will reply with a 64-hex-char nonce.  Paste it here:

Nonce: <paste the 64-hex nonce>
==> nonce saved to /home/ubuntu/.mtc-ca-data/api.widget-corp.example/nonce.txt
==> running bootstrap_leaf ...

==> DONE. identity at /home/ubuntu/.TPM/api.widget-corp.example
```

Useful flags:

| Flag | Meaning |
|---|---|
| `--label L` | store under `~/.TPM/<domain>-<label>/` so you can run prod + staging leaves side by side |
| `--nonce HEX` | skip `issue_leaf_nonce` and the interactive prompt; use this when you already have a nonce in hand (e.g. from a messaging app) |
| `--make-default` | atomically re-point `~/.TPM/default` at this new identity |
| `--force-keygen` | regenerate the keypair even if `~/.mtc-ca-data/<domain>/` has material |
| `--no-prompt` | non-interactive: refuses (exit 1) if no local CA and no `--nonce` |
| `--dry-run` | run through keygen + nonce acquisition, skip `bootstrap_leaf` |

---

## Manual three-step path

When you want to watch each phase separately, or you need to route
the nonce through a DNS-email workflow rather than a shared prompt:

```
# On the leaf box:
# 1. keygen
create_leaf_keypair.py --domain api.widget-corp.example

# 2. send ~/.mtc-ca-data/api.widget-corp.example/public_key.pem to
#    the CA operator out of band (email, signal, scp, etc.)

# On the CA operator's box:
# 2a. issue a nonce (MQC over 8446, requires the CA's ~/.TPM/*-ca/ identity)
issue_leaf_nonce --domain api.widget-corp.example \
                 --key-file /path/to/received/public_key.pem \
                 --server  ca.widget-corp.example:8446
# → prints the 64-hex-char nonce and saves to
#   ~/.mtc-ca-data/api.widget-corp.example/nonce.txt

# 2b. send the 64-hex nonce back to the leaf operator

# Back on the leaf box:
# 3. enroll — bootstrap_leaf auto-reads nonce.txt if it's in
#    ~/.mtc-ca-data/<domain>/, or pass --nonce HEX explicitly
echo '<64-hex nonce>' > ~/.mtc-ca-data/api.widget-corp.example/nonce.txt
bootstrap_leaf --domain api.widget-corp.example \
               --server ca.widget-corp.example:8445
```

`register-leaf.sh` is a convenience wrapper around exactly these
steps with the two-mode detection and interactive paste-prompt glued
between them.

---

## Files created

### On the leaf box

| Path | Written by | Purpose |
|---|---|---|
| `~/.mtc-ca-data/<domain>/private_key.pem` | `create_leaf_keypair.py` | ML-DSA-87 private key (mode 0600) |
| `~/.mtc-ca-data/<domain>/public_key.pem` | `create_leaf_keypair.py` | ML-DSA-87 public key |
| `~/.mtc-ca-data/<domain>/public_key.txt` | `create_leaf_keypair.py` | human-readable dump for auditing |
| `~/.mtc-ca-data/<domain>/nonce.txt` | `issue_leaf_nonce` OR `register-leaf.sh` (paste) | 64-hex-char enrollment nonce (mode 0600, consumed on bootstrap success) |
| `~/.TPM/<domain>/certificate.json` | `bootstrap_leaf` | MTC standalone_certificate (Merkle log entry + inclusion proof + cosignature) |
| `~/.TPM/<domain>/index` | `bootstrap_leaf` | log index (plain text) |
| `~/.TPM/<domain>/private_key.pem` | `bootstrap_leaf` | copied from `~/.mtc-ca-data/` |
| `~/.TPM/<domain>/public_key.pem` | `bootstrap_leaf` | copied from `~/.mtc-ca-data/` |
| `~/.TPM/default` | `bootstrap_leaf` (create-if-missing) | symlink to the new `<domain>` dir; `register-leaf.sh --make-default` forces atomic re-point |

After enrollment, day-to-day operation (MQC connect, renew, verify)
runs off `~/.TPM/` — `~/.mtc-ca-data/` is only re-used on the next
renewal (which rewrites it with fresh keys).

### On the CA box (in same-machine mode)

Same `~/.mtc-ca-data/<leaf-domain>/` paths are written by
`create_leaf_keypair.py` and `issue_leaf_nonce`. In cross-machine
mode the CA box only writes the nonce to *its* local
`~/.mtc-ca-data/<leaf-domain>/nonce.txt` — the CA operator then
relays the nonce string to the leaf operator manually.

> **Security note.** Private key appears in both `~/.mtc-ca-data/` and
> `~/.TPM/` post-enrollment — tracked as TODO #33 in
> `README-bugsandtodo.md`.

---

## State changes on the server

Two rows are touched:

| Table / state | Change |
|---|---|
| `mtc_enrollment_nonces` | **one INSERT** when `issue_leaf_nonce` runs: `(nonce, domain, fp, ca_index, label, status='pending', expires_at = now+15min)`. **UPDATE to `status='consumed'`** when `bootstrap_leaf` succeeds. Partial unique index enforces one-pending-nonce per `(domain, label)`. |
| `mtc_certificates` (Neon) | one new row at the next log index, holding the MTC standalone_certificate JSONB |
| Merkle tree (in-memory + disk) | one new entry appended; checkpoint + cosignature updated |
| `mtc_revocations` | unchanged |

Re-running `register-leaf.sh` for an already-enrolled domain is
guarded client-side (existing-identity warning) but not server-side.
A successful re-enrollment creates a second log entry with the same
`(subject, fingerprint)` — that's the TODO #32 ghost-entry problem
bootstrap_ca has. Your local `~/.TPM/` points at the latest index;
the earlier index sits in the log until revoked.

---

## Calls made (wire-level)

### Same-machine mode

1. **leaf → CA box (internal `issue_leaf_nonce`)** — same process tree;
   no network.
2. **CA → MTC server, MQC :8446** — POST `/enrollment/nonce` with the
   leaf's public key fingerprint. Server inserts a row into
   `mtc_enrollment_nonces`, returns the nonce string. MQC handshake
   authenticates the CA via its existing cert.
3. **Leaf → MTC server, TCP :8445** — X25519 DH handshake (plaintext
   JSON in → plaintext JSON out → both derive an AES-128 key via
   HKDF-SHA256).
4. **Leaf → MTC server (DH-encrypted)** — enrollment payload:
   `{subject, public_key_pem, key_algorithm, validity_days, enrollment_nonce, extensions}`.
5. **Server** — validates the nonce (`mtc_db_validate_and_consume_nonce`):
   matches domain, fingerprint, not expired, marks consumed.
6. **Server** — Neon `INSERT INTO mtc_certificates`; appends to
   Merkle tree; cosigns.
7. **Server → leaf (DH-encrypted)** — `{standalone_certificate}` response.

### Cross-machine mode

Same as above, except step 1 happens as a human-driven out-of-band
message (email, Signal, scp, shared clipboard), and step 2 runs on
the CA operator's machine, not the leaf's.

---

## Failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `Error: mqc_connect to HOST:8446 failed` (via `issue_leaf_nonce`) | MQC server not reachable, or local CA's MQC cert rejected | check server is up, check `show-tpm --verify` against the CA identity |
| `server returned HTTP 403` + `no registered CA exists for this domain` | the parent domain doesn't have a CA enrolled yet | the CA operator must `register-ca.sh` first |
| `bootstrap_leaf ... Error: nonce expired` | 15-minute TTL lapsed between `issue_leaf_nonce` and `bootstrap_leaf` | re-run `issue_leaf_nonce` or `register-leaf.sh` |
| `bootstrap_leaf ... Error: nonce does not match fingerprint` | the leaf's public key changed between nonce issuance and bootstrap (key regenerated) | re-run with the current key, or `--force-keygen` to match nonce to a fresh key |
| `ERROR: no --nonce given, no local CA, and stdin is not a tty` | cross-machine batch mode without a nonce | re-run interactively, or obtain the nonce out-of-band and pass `--nonce HEX` |
| Paste-prompt rejects nonce as "must be 64 hex chars" | stray whitespace, wrong copy, or truncated | verify length with `wc -c`, re-paste; trimming is already applied |
| `A leaf identity for <domain> already exists` warning | re-enrolling over a live identity | answer `n` (default) to abort; to rotate keys, use `check-renewal-cert --force <domain>` instead |
| `existing leaf identity at <dir> is REVOKED.` + exit 1 | CA has revoked this cert | register-leaf.sh refuses and the server enforces the same policy. To rotate keys, use `check-renewal-cert` (MQC bypasses the gate). To unrevoke, open an issue at https://github.com/cpsource/postWolf/issues. |

---

## Renewal

Leaf renewal uses the same path as CA renewal: `check-renewal-cert`
(installed by both kits) walks `~/.TPM/` daily under cron and renews
any identity within 5 days of expiry via the MQC `/renew-cert`
endpoint. Nonces are not involved — MQC identity *is* the auth.

Enable the daily cron with:

```
sudo /usr/local/sbin/setup-recert-crond.sh --start
```

See `README-bugsandtodo.md` items #23 and #24 for design notes.

---

## Revocation

To revoke a leaf identity, the CA operator runs:

```
# On the CA box:
revoke-key --target-index <N> --reason "key compromise"
```

After revocation:
- `show-tpm --verify` on the leaf box fails the revocation check.
- The MQC handshake rejects the revoked identity at connect time.
- `register-leaf.sh` refuses re-enrollment for that specific
  identity directory (client-side guard keyed on the local
  `certificate.json`'s cert_index).
- `mtc_bootstrap.c` refuses too (server-side gate): if a prior log
  entry with the **same subject AND same public-key fingerprint**
  is revoked, the DH-bootstrap endpoint rejects the request even
  when the nonce validates.

**Label-aware design.** Labels (`~/.TPM/<domain>-Jane/` vs
`~/.TPM/<domain>-John/`) are local-only — the cert subject is just
`<domain>` for all of them. So the server-side gate matches on the
**public-key fingerprint** as well as the subject: revoking Jane's
cert blocks re-enrollment of *her specific key*, not John's
(different key, different fingerprint) or a fresh Jane keypair
(`--force-keygen` → new fingerprint). The CA-issued nonce remains
the primary authorization; this gate is defense-in-depth against
resurrecting a known-revoked key.

**Recovery paths:**

1. **Routine key rotation (preferred).** If the goal is just to
   rotate the key (e.g. suspected compromise), use
   `check-renewal-cert --force <domain>` instead of re-running
   `bootstrap_leaf`. Renewal runs over MQC (`/renew-cert`) using
   the still-valid identity and **bypasses the bootstrap revocation
   gate** by design. Automate it with
   `sudo /usr/local/sbin/setup-recert-crond.sh --start`.

2. **Fresh key re-enrollment.** The CA operator revokes the
   compromised key, you run
   `register-leaf.sh --force-keygen ...` to generate a brand new
   keypair. New fingerprint → server's revocation gate doesn't
   match → enrollment proceeds normally after the CA issues a new
   nonce.

3. **Unrevoke (rare).** If the revocation was issued in error and
   you genuinely want the old cert "alive" again, the CA operator
   has to request an unrevoke from the server operator — MTC's
   append-only log has no native unrevoke, so the `mtc_revocations`
   table needs a DB-level edit. Open an issue at
   <https://github.com/cpsource/postWolf/issues> with the domain and
   cert_index. Future work (TODO #34) adds a self-service
   revocation-management page.

Unlike the CA-side policy (which bans the whole subject after
revocation), the leaf policy only bans the specific compromised
key. Different CAs manage the domain, so multi-label coexistence
must keep working.
