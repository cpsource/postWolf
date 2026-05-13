# deploy-qsh — qsh deployment kit

This tarball lets you run **qsh** (post-quantum interactive shell over
MQC, port 1024) on a fresh Linux box without checking out or building
the postWolf source tree.

It contains:

| File / dir | Purpose |
|---|---|
| `qsh` | Pre-built client binary (links libpostWolf + 4 system libs) |
| `check-qsh-deps.py` | Runtime-library audit — run this first |
| `Makefile` | `make install` / `uninstall` / `run` targets |
| `postWolf.config` | Minimal `/etc/postWolf/config` template (points qsh at the MTC log server) |
| `myconf.aug` | Augeas lens that parses `postWolf.config` (qsh can't read it without this) |
| `TPM/factsorlie.com/` | MTC identity (PEM keys + cosignature-verified cert) |
| `README.md` | This file |

> **Trust note.**  `TPM/factsorlie.com/private_key.pem` is real ML-DSA-87
> private key material.  Whoever holds this tarball can open MQC
> sessions as `factsorlie.com`.  Move the bundle over a private
> channel and don't leave it on shared storage.

## Quick start

```bash
tar xzf deploy-qsh.tar.gz
cd deploy-qsh

# 1. Audit runtime deps; install whatever's missing.
make check

# 2. (One-time, off-kit) install libpostWolf — the only dep not on
#    the apt list.  Easiest path is to copy /usr/local/lib/libpostWolf.so*
#    (the .so + .so.44 + .so.44.0.0 chain) from a host where postWolf
#    is installed, drop them in /usr/local/lib on this host, then:
sudo ldconfig

# 3. Install qsh + the bundled identity.  `make install` runs `check`
#    first, then `install-bin` (sudo into /usr/local/bin) and
#    `install-tpm` (per-user into ~/.TPM/).
make install

# 4. Run it.
make run             # uses HOST=factsorlie.com, the bundled identity
# or directly:
qsh --host=factsorlie.com --tpm-path=~/.TPM/factsorlie.com
```

### Make targets in this kit

```
make                # show help
make check          # audit ./qsh's runtime libraries
make install        # check + sudo install qsh + sudo install config + per-user install TPM
make install-bin    # just the qsh binary (sudo)
make install-config # just /etc/postWolf/config (sudo, refuses to overwrite)
make install-tpm    # just the TPM identity (refuses to overwrite)
make uninstall      # remove qsh + config + ~/.TPM/factsorlie.com
make run            # quick smoke: qsh --host=$HOST --tpm-path=~/.TPM/...
```

Overrides: `make install IDENTITY=other.com HOST=other.com PREFIX=/opt`.

### Why `make install-config` matters

Without `/etc/postWolf/config`, qsh falls back to `localhost:8444` for
the MTC log-server query and the cosigner-pubkey fetch fails with:

```
[mqc] cannot fetch CA pubkey from localhost:8445 (bootstrap)
qsh: cannot load CA cosigner pubkey from localhost:8444
```

`make install-config` writes a one-key config pointing at the
correct log server (default: `https://factsorlie.com:8446`) **and**
installs the Augeas `Myconf` lens at
`/usr/local/share/augeas/lenses/myconf.aug`.  qsh's config reader
goes through Augeas, so without the lens it returns NULL even when
the file is present — that's why the kit ships both.

Edit `postWolf.config` before running `make install` if you need a
different URL.

## CLI flags

```
qsh --host=HOST [--port=N] [--tpm-path=PATH] [--user=NAME]
    [--mtc-server=URL] [--expected-name=NAME]
```

- `--host` — qshd server hostname or IP (required).
- `--port` — TCP port qshd listens on (default 1024, or `[qsh]
  qshd-port` from `/etc/postWolf/config`).
- `--tpm-path` — path to your MTC identity dir.  `~/` expands to
  `$HOME/`.
- `--user=NAME` — shortcut for `--tpm-path=~/.TPM/NAME`.
- `--mtc-server=URL` — override the MTC log server (default reads
  `global/url-server` from `/etc/postWolf/config`; usually
  `https://factsorlie.com:8446`).
- `--expected-name=NAME` — override the subject-string check
  (default: derived from `--host`).

## Troubleshooting

**`mqc_ctx_new failed (tpm-path=...)`** — `--tpm-path` doesn't point
at a valid identity dir.  Confirm `~/.TPM/factsorlie.com/` exists
and contains `private_key.pem`, `public_key.pem`, `certificate.json`,
`index`.

**`cannot load CA cosigner pubkey from https://factsorlie.com:8446`**
— qsh can't reach the MTC log server (port 8446) to fetch the
current cosigner pubkey.  Check DNS / firewall on the log-server
hostname.

**`connection lost` repeatedly** — qshd is up but rejecting you.
Most likely the `/etc/qsh/qshd/config` ACL on the server doesn't
include your cert_index.  Look in the server's `journalctl -u qshd`
for `DENIED by ACL: peer_index=N` and ask the server operator to
add an `allow N` line.

**`[MQC-SECURITY ...] first-frame read failed`** in the server log
— your qsh side aborted before sending the first handshake frame.
Most often a DNSSEC pin failure or a missing `libunbound.so.8` /
`libcrypto.so.3` on the client side.  Re-run `check-qsh-deps.py`.

## What qsh is

A post-quantum interactive shell.  Like ssh in feel, but:

- **No X.509, no RSA, no ECC.**  Authentication is ML-DSA-87
  signatures verified through Merkle inclusion + cosignature.
- **No CRL fetch.**  Revocation is checked through the MTC log
  (`mtc-revocation-policy = mandatory` by default; fail-closed).
- **ML-KEM-768 key exchange + AES-256-GCM session encryption.**
- **Real PTY shell** — the server `forkpty()`s `bash --login` per
  session.

Wire spec: `socket-level-wrapper-MQC/README-MQC-specifications.md`
in the postWolf source tree (not bundled in this kit).
