# postWolf leaf kit

A minimal install of the postWolf client-side tooling — enough to
enroll a leaf identity under an existing MTC CA and use it. No
database, no Redis, no server daemon.

## What's in the kit

| Path | Purpose |
|------|---------|
| `bin/bootstrap_leaf` | First-time leaf enrollment (needs a CA-issued nonce). |
| `bin/show-tpm`       | Inspect the local identity; `--verify` walks the full trust chain (including revocation) against the CA's log. |
| `bin/create_leaf_keypair.py` | Generate a post-quantum keypair (default ML-DSA-87; EC-P256 / Ed25519 also supported) via `openssl35`. |
| `lib/libpostWolf.so*` | wolfSSL-derived shared library used by the tools. |
| `socket-level-wrapper-MQC.tar.gz` | Source + prebuilt `libmqc.a` for the MQC wrapper. The installer extracts headers (`/usr/local/include/mqc/`) and the static library (`/usr/local/lib/libmqc.a`). |
| `mqc.pc`             | pkg-config file installed to `/usr/local/lib/pkgconfig/mqc.pc` so downstream C code can `pkg-config --cflags --libs mqc`. |
| `install-leaf-kit.sh` | Installs everything to `/usr/local/` — must be run with sudo. |
| `VERSION`            | Git describe of the tree this kit was built from. |

## Install

```bash
tar xzf postWolf-leaf-kit-<version>.tar.gz
cd payload
sudo bash install-leaf-kit.sh
```

The installer:

1. apt-installs the runtime library dependencies (`libjson-c5`,
   `libcurl4`, `libpq5`, a `libhiredis` variant).
2. **Builds OpenSSL 3.5 from source** the first time through, into
   `/usr/local/ssl/`, and drops a wrapper at `/usr/local/bin/openssl35`
   (the system `openssl` on your distro almost certainly pre-dates
   ML-DSA-87 and stays untouched). Expect ~5–10 minutes on first run;
   subsequent re-installs detect the existing `openssl35` and skip the
   rebuild. Source tree lives at `/usr/local/src/openssl` so `git pull`
   picks up upstream patches next time.
3. Copies `libpostWolf.so*` to `/usr/local/lib/` and runs `ldconfig`.
4. Installs the MQC library: headers to `/usr/local/include/mqc/`,
   `libmqc.a` to `/usr/local/lib/`, `mqc.pc` to
   `/usr/local/lib/pkgconfig/`.
5. Installs the leaf tools to `/usr/local/bin/`.
6. Final `ldd` check on each tool; prints any unresolved `.so` names.

## Enroll

Leaf enrollment is a two-party handshake with the CA operator — they
authorise your public key by issuing you a 15-minute-TTL nonce.

**1. Generate a leaf key pair** (if you don't already have one):

```bash
create_leaf_keypair.py --domain <DOMAIN>
# → writes ~/.mtc-ca-data/<DOMAIN>/private_key.pem + public_key.pem
# Pass --algorithm EC-P256 or Ed25519 if you want something else than
# the default ML-DSA-87.
```

Send `~/.mtc-ca-data/<DOMAIN>/public_key.pem` to your CA operator out of band.

**2. CA operator issues a nonce** (runs on their side):

```bash
issue_leaf_nonce --domain <DOMAIN> --key-file leaf-pub.pem
# → prints a 64-hex-char nonce; they send it to you
```

The nonce is bound to your public key fingerprint and to the domain —
it cannot be used for any other key or domain.

**3. Bootstrap your identity** (on your side):

```bash
bootstrap_leaf --domain <DOMAIN> \
               --server <CA-HOST>:8445 \
               --nonce  <64-hex-char nonce>
```

This runs an X25519 DH exchange over the CA's bootstrap port (8445),
submits your CSR, and receives the issued certificate. Everything lands
in `~/.TPM/<DOMAIN>/`:

```
~/.TPM/<DOMAIN>/
    private_key.pem        # mode 0600
    public_key.pem
    certificate.json       # MTC cert + Merkle inclusion proof + cosignature
    index                  # log index
```

## Verify

```bash
show-tpm --verify
```

Walks the full chain: fetches the log's current root from the CA's
MQC port (8446), replays your inclusion proof, verifies the Ed25519
cosignature over the subtree containing your cert, and checks
revocation. On first run it TOFU-pins the CA's cosigner public key
into `~/.TPM/ca-cosigner.pem`; any future fingerprint change is a
signal worth investigating, not silently accepting.

## Revocation

Leaves don't have revocation authority — only a CA can revoke leaves
under its domain. That's deliberate, and it's why `revoke-key` is not
shipped in this kit.

If your own cert gets revoked by your CA, `show-tpm --verify` will
fail on the revocation check, which is how you find out. No action is
required on your side; rotating your identity means running
`bootstrap_leaf` again with a fresh nonce from the CA.

To actively revoke a leaf (including your own), you need the
postWolf **CA** kit (`postWolf-ca-kit-*.tar.gz`) installed alongside a
registered CA identity in `~/.TPM/<domain>-ca/`.

## Building your own MQC client

The kit installs enough to compile + link against MQC directly:

```c
#include <mqc/mqc.h>
#include <mqc/mqc_peer.h>
/* ... */
mqc_ctx_t *ctx = mqc_ctx_new(&cfg);
mqc_conn_t *c  = mqc_connect(ctx, "factsorlie.com", 8446);
```

```bash
# Compile:
cc $(pkg-config --cflags mqc) my_client.c -o my_client $(pkg-config --libs mqc)
```

`pkg-config --cflags mqc` returns `-I/usr/local/include/mqc` plus the
upstream postWolf cflags via the `Requires:` chain. `pkg-config --libs mqc`
returns `-L/usr/local/lib -lmqc -lpostWolf`, so static `libmqc.a` gets
resolved plus the dynamic library under it.

## Uninstall

```bash
sudo rm -f /usr/local/bin/{bootstrap_leaf,show-tpm,create_leaf_keypair.py}
sudo rm -f /usr/local/lib/libpostWolf.so*
sudo rm -f /usr/local/lib/libmqc.a
sudo rm -f /usr/local/lib/pkgconfig/mqc.pc
sudo rm -rf /usr/local/include/mqc
sudo rm -rf /usr/local/share/doc/postWolf-leaf
sudo ldconfig

# Optional: wipe openssl35 too (the installer built it into /usr/local/ssl)
sudo rm -rf /usr/local/ssl /usr/local/bin/openssl35 /usr/local/src/openssl

# Optional: rm -rf ~/.TPM/   (deletes your identity!)
```

## More

- Full project overview: [postWolf README](https://github.com/cpsource/postWolf).
- Server-side endpoint reference:
  `mtc-keymaster/server2/c/README-using-mtc-server.md` in the repo.
- Open issues / roadmap: `mtc-keymaster/README-bugsandtodo.md`.
