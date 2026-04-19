# CA Registration

How to register a new MTC Certificate Authority for a domain you
control. The end state: your CA identity is in
`~/.TPM/<domain>-ca/`, the server has your enrollment in its Merkle
log, and you can issue leaf-enrollment nonces for subdomains under
`<domain>`.

---

## Overview

"Registering a CA" in postWolf means four things happening in order:

1. **Local keygen.** You generate an ML-DSA-87 keypair and wrap the
   public key in a classical X.509 self-signed CA certificate. That
   X.509 cert is never used to sign leaves — it exists only so the
   MTC server has something structurally parseable to check your
   domain ownership against.
2. **DNS publication.** You publish a TXT record at
   `_mtc-ca.<domain>` binding your domain to the SHA-256 fingerprint
   of your public key. Controlling the DNS record *is* the proof of
   domain ownership — no nonce, no signature, no dance.
3. **DH bootstrap.** You connect to the MTC server's port 8445, do
   an X25519 key exchange (for confidentiality of the subsequent
   enrollment payload), and send the cert.
4. **Server mints MTC cert.** The server fetches the TXT record,
   verifies the fingerprint, issues an MTC `standalone_certificate`
   (Merkle log entry + inclusion proof + cosignature), and returns
   it. You save it under `~/.TPM/<domain>-ca/`.

---

## Fast path (recommended)

After installing `kit-CA`, one command walks you through the whole
thing:

```
register-ca.sh --domain ops.widget-corp.example \
               --server ca.factsorlie.com:8445
```

What happens:

```
==> generating ML-DSA-87 keypair + X.509 CA cert for ops.widget-corp.example
... [create_ca_cert.py output] ...

Publish this DNS TXT record at your DNS provider:

    _mtc-ca.ops.widget-corp.example.  IN  TXT  "v=mtc-ca1; fp=sha256:5052154e..."

After publishing the record, proceed? [Y/n/q] <Enter>
==> polling DNS via 8.8.8.8 (up to 5 min) ...
  DNS propagation: [######......................] 1:00 / 5:00  attempt 6/30
  DNS propagation: [##############################] 5:00 / 5:00  visible ✓
==> running bootstrap_ca ...
... [DH handshake, enrollment, MTC cert response] ...

==> DONE. identity at /home/ubuntu/.TPM/ops.widget-corp.example-ca
    ~/.TPM/default -> ops.widget-corp.example-ca
```

Prompt semantics at the publish-gate and timeout prompt:

| Answer | Effect |
|---|---|
| `Y` (default, just Enter) | proceed — poll DNS / wait another 5 min |
| `n` | skip polling, try `bootstrap_ca` immediately (advanced: you're sure DNS is already visible) |
| `q` | abort cleanly with exit 1 |

Useful flags:

| Flag | Meaning |
|---|---|
| `--label L` | store under `~/.TPM/<domain>-<label>-ca/` so you can run prod + staging CAs side by side |
| `--make-default` | atomically re-point `~/.TPM/default` at this new identity even if one already exists |
| `--force-keygen` | regenerate the keypair even if `~/.mtc-ca-data/<domain>/` already has material |
| `--no-prompt` | non-interactive: accept defaults at every prompt, DNS timeout becomes fatal (cron/CI safe) |
| `--dry-run` | run through keygen + TXT + DNS poll, skip `bootstrap_ca` |
| `RESOLVER=1.1.1.1 …` | env override for the DNS poll resolver |

---

## Manual three-step path

Useful for debugging, for running each phase under a different user,
or for integrating with a DNS-API script that publishes TXT
programmatically.

```
# 1. keygen
create_ca_cert.py --domain ops.widget-corp.example

# 2. print DNS TXT record
ca_dns_txt.py ~/.mtc-ca-data/ops.widget-corp.example/ca_cert.pem
# → _mtc-ca.ops.widget-corp.example.  IN TXT  "v=mtc-ca1; fp=sha256:..."

# publish that record at your DNS provider, then:
ca_dns_txt.py --check ~/.mtc-ca-data/ops.widget-corp.example/ca_cert.pem
# → [PASS] ops.widget-corp.example — MATCH at _mtc-ca.ops.widget-corp.example

# 3. enroll
bootstrap_ca --domain ops.widget-corp.example \
             --server ca.factsorlie.com:8445
```

`register-ca.sh` is a convenience wrapper around exactly these three
commands with polling and safety checks glued between them.

---

## Files created

| Path | Written by | Purpose |
|---|---|---|
| `~/.mtc-ca-data/<domain>/private_key.pem` | `create_ca_cert.py` | ML-DSA-87 private key (mode 0600) |
| `~/.mtc-ca-data/<domain>/public_key.pem` | `create_ca_cert.py` | ML-DSA-87 public key |
| `~/.mtc-ca-data/<domain>/public_key.txt` | `create_ca_cert.py` | human-readable dump for auditing |
| `~/.mtc-ca-data/<domain>/ca_cert.pem` | `create_ca_cert.py` | X.509 self-signed CA cert wrapping the public key |
| `~/.TPM/<domain>-ca/certificate.json` | `bootstrap_ca` | MTC standalone_certificate (Merkle log entry + inclusion proof + cosignature) |
| `~/.TPM/<domain>-ca/index` | `bootstrap_ca` | log index (plain text) |
| `~/.TPM/<domain>-ca/private_key.pem` | `bootstrap_ca` | copied from `~/.mtc-ca-data/` |
| `~/.TPM/<domain>-ca/public_key.pem` | `bootstrap_ca` | copied from `~/.mtc-ca-data/` |
| `~/.TPM/<domain>-ca/ca_cert.pem` | `bootstrap_ca` | copied from `~/.mtc-ca-data/` |
| `~/.TPM/default` | `bootstrap_ca` (create-if-missing) | symlink to the new `<domain>-ca` dir; `register-ca.sh --make-default` forces atomic re-point when one already exists |

After enrollment, day-to-day operation (MQC connect, revoke-key,
renew) runs off `~/.TPM/` — `~/.mtc-ca-data/` is only read again
when you re-emit the DNS TXT record (`ca_dns_txt.py`) or on the next
cert renewal (`check-renewal-cert` rewrites `~/.mtc-ca-data/`
with fresh keys).

> **Security note.** The private key lives in two places today
> (`~/.mtc-ca-data/<domain>/private_key.pem` and
> `~/.TPM/<domain>-ca/private_key.pem`). Tracked as TODO #33 in
> `README-bugsandtodo.md`.

---

## State changes on the server

| Table / state | Change |
|---|---|
| `mtc_certificates` (Neon) | one new row at the next log index, holding the MTC standalone_certificate JSONB |
| Merkle tree (in-memory + disk) | one new entry appended, checkpoint + log cosignature updated |
| `mtc_enrollment_nonces` | **unchanged** — CA enrollment never touches nonces (only leaf does) |
| `mtc_revocations` | unchanged |

> **Note:** re-running `bootstrap_ca` (or `register-ca.sh` against
> an existing identity after answering "Proceed anyway? y") creates
> a *second* log entry with the same `(subject, fingerprint)`. The
> server does not yet de-duplicate. Tracked as TODO #32. Your local
> state is fine — the new index overwrites the old one in
> `~/.TPM/` — but the old index lingers in the log forever unless
> you revoke it explicitly.

---

## Calls made (wire-level)

1. **Client → `dig @<resolver>`** — only during the client-side poll;
   server does its own DNS query independently.
2. **Client → TCP :8445** — X25519 DH handshake: client sends its
   ephemeral pubkey in plaintext JSON, server replies with its
   ephemeral pubkey + salt, both derive an AES-128 key via
   HKDF-SHA256.
3. **Client → server (DH-encrypted)** — enrollment payload:
   `{subject, public_key_pem, ca_certificate_pem, validity_days, extensions{ca_certificate_pem, is_ca:true}}`.
4. **Server → `res_query(_mtc-ca.<domain>, TXT)`** — against its
   configured resolver, expects `v=mtc-ca1; fp=sha256:<hex>`.
5. **Server → Neon `INSERT INTO mtc_certificates`** — commits the new
   log entry; updates in-memory tree; cosigns.
6. **Server → client (DH-encrypted)** — response: the new
   standalone_certificate JSON.

---

## Failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `register-ca.sh: dig: command not found` | `dnsutils` missing | `sudo apt install dnsutils` (should be installed by `install-ca-kit.sh`) |
| `ca_dns_txt.py ... ERROR: openssl35 not in PATH` | OpenSSL 3.5+ not installed | `buildopenssl3.5.sh` from the kit (installed by `install-ca-kit.sh`) |
| Publish-gate prompt loops with wrong-key fingerprint | TXT record for a stale key | delete stale TXT, publish the one `register-ca.sh` just printed |
| DNS poll times out | propagation slow; wrong TXT value; DNS API hasn't committed | answer `Y` to wait another 5 min; verify with `dig @8.8.8.8 TXT _mtc-ca.<domain>` manually |
| Server rejects with `CA certificate rejected: DNS validation failed` | client-side poll saw the record but server's resolver still sees old/cached data | wait a minute and re-run; keys are reused |
| `WARNING: An active CA identity for <domain> already exists` | you're re-registering an existing healthy CA — this creates a ghost log entry | default answer aborts; to rotate keys, use `check-renewal-cert --force <domain>-ca` instead |
| `existing CA identity at <dir> is EXPIRED; … Proceeding` | no action required | register-ca.sh proceeds automatically — the old identity is dead, a fresh one is appropriate |
| `existing CA identity at <dir> is REVOKED; … Proceeding` | no action required | same — re-enrollment is the right move |

---

## Renewal

CA renewal is a separate path, not a re-run of registration. The MTC
server exposes `/renew-cert` on port 8446 (MQC-authenticated), and
`check-renewal-cert` (installed by `kit-CA`) walks `~/.TPM/` daily
under cron, renewing any identity within 5 days of expiry:

```
sudo /usr/local/sbin/setup-recert-crond.sh --start
```

Renewal keeps the same subject, rotates the keypair, issues a new
MTC cert at a new log index. DNS is not involved (MQC identity is
the auth). See `README-bugsandtodo.md` items #23 and #24.

---

## Revocation and re-registration

To retire a CA identity for good:

```
revoke-key --target-index <N> --reason "key compromise"
```

To replace with a fresh key on the same domain:

1. `revoke-key --target-index <N>` — mark the old one revoked.
2. `register-ca.sh --domain <domain> --server …` — re-runs; the
   existing-identity guard detects the revocation and proceeds
   without prompting.

There's no formal "deregister" step — the Merkle log is append-only.
Revocation is how you invalidate.
