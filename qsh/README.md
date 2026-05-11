# qsh — post-quantum shell over MQC

Interactive remote-shell over [MQC](../socket-level-wrapper-MQC), the
postWolf post-quantum TCP transport.  Like SSH, but with no TLS, no
X.509, no CRL: peer identity is an MTC certificate (cert_index plus a
Merkle inclusion proof + cosignature) and the session is encrypted under
keys derived from an ML-KEM-768 exchange.

## Features

- Full PTY support — vi, htop, any interactive program
- Post-quantum mutual authentication
  - ML-KEM-768 key exchange
  - ML-DSA-87 identity signatures
  - Merkle-tree inclusion proof + log cosignature
  - Fail-closed revocation check against the transparency log
- Window-resize (SIGWINCH) forwarding
- AES-256-GCM session encryption, per-direction keys
- Multi-client via fork-per-connection on the server
- No passwords, no manual key distribution: identity comes from the
  caller's `~/.TPM/<dns>[-<label>]/` directory, same as every other
  postWolf tool

## Directory layout

```
qsh/
  qsh/                  Client source + Makefile
  qshd/                 Server source + Makefile + systemd unit
  certs/, crl/, tools/, docs/   Historical (QUIC-era) — not used by the MQC build
  README-QUIC.md        Historical README from the QUIC version
```

The old `certs/`, `crl/`, `make-certs.sh`, `client-ext.cnf`, `tools/`,
and `docs/` trees describe the QUIC/TLS flow and play no part in the
MQC build.  They're left in place for archaeology; ignore them.

## Prerequisites

A working postWolf install:

```bash
# from the repo root
make -f Makefile.tools && sudo make -f Makefile.tools install
```

That gives you `libpostWolf.so`, the in-tree `libmqc.a`, and the MTC
client tools (`bootstrap_leaf`, `show-tpm`, …).  qsh/qshd link against
both.

The caller also needs an MTC identity under `~/.TPM/`.  Run
`bootstrap_leaf` (per the rest of the postWolf docs) once per identity.

## Build

```bash
cd qsh/qshd && make    # produces qshd
cd qsh/qsh  && make    # produces qsh
```

Both compile with `-Wall -Wextra -Werror`.

## Usage

### Server

```bash
qshd --tpm-path=~/.TPM/factsorlie.com [--port=2222] [--user=ubuntu]
```

| Flag | Meaning |
|---|---|
| `--tpm-path=PATH` | Server's MTC identity dir.  Required. |
| `--port=N` | TCP port (default `2222`). |
| `--user=NAME` | Drop privileges to this unix account after `forkpty` (e.g. `--user=ubuntu`).  Optional; without it, sessions run as whatever user `qshd` runs as. |
| `--mtc-server=URL` | Override `/etc/postWolf/config global/url-server`. |

The server logs every successful accept with the verified peer subject
and cert_index:

```
[qshd] accepted 'factsorlie.com' from 127.0.0.1 (peer_index=74)
[qshd:745402] shell started for 'factsorlie.com' (80x24)
```

### Client

```bash
qsh --host=factsorlie.com [--port=2222] [--user=Alice]
```

| Flag | Meaning |
|---|---|
| `--host=HOST` | Server hostname or IP.  Required. |
| `--port=N` | TCP port (default `2222`). |
| `--tpm-path=PATH` | Client's MTC identity dir.  Default: `~/.TPM/default`. |
| `--user=NAME` | Shortcut for `--tpm-path=~/.TPM/NAME`. |
| `--mtc-server=URL` | Override `/etc/postWolf/config global/url-server`. |
| `--expected-name=NAME` | Expected server MTC subject (default: the dialed hostname).  Required when dialing by IP literal. |

Example:

```
$ qsh --host=factsorlie.com --user=Alice
qsh: connecting to factsorlie.com:2222 via MQC...
qsh: connected — server subject 'factsorlie.com' (peer_index=72)
ubuntu@factsorlie:~$ whoami
ubuntu
ubuntu@factsorlie:~$ exit
qsh: disconnected
```

If the handshake fails for any reason (peer cert not in the log,
cosignature mismatch, revoked cert, expected-name mismatch, etc.) the
client prints a diagnostic to stderr (look for `[MQC-SECURITY ...]`)
and reconnects up to five times before giving up.

## Revocation

There is no `crl/` directory and no per-cert revocation file to manage.
MQC's `mqc_peer_verify` queries the transparency log for a revocation
record at every handshake, fail-closed on query error.  To revoke
`Alice`, revoke her cert via the CA workflow (`revoke-key` per the
postWolf docs) and the next `qsh` handshake from her will be refused
by `qshd` before any shell is forked.

## Wire format

After the MQC handshake completes, the two ends exchange typed messages
over the single MQC bytestream.  MQC preserves message boundaries, so
every `mqc_write` arrives as one `mqc_read` of the same length — the
framing is just a 1-byte type at offset 0 followed by a type-specific
payload:

| Type | Direction | Payload | Meaning |
|---|---|---|---|
| `0x01 OPEN_SHELL` | C → S | rows(u16 BE) cols(u16 BE) | First frame; triggers `forkpty` + `bash` on the server |
| `0x02 DATA`       | both  | raw bytes                 | shell stdin (C→S) and shell stdout/stderr (S→C) |
| `0x03 RESIZE`     | C → S | rows(u16 BE) cols(u16 BE) | `ioctl(TIOCSWINSZ)` on the PTY |
| `0x04 SHELL_EXIT` | S → C | empty                     | Sent when `read(pty_master)` returns 0; client exits cleanly |

## Security summary

All MQC v0 security properties (transcript binding, Finished MAC, AEAD
AAD, per-direction keys, mandatory revocation, expected-identity check,
strict JSON parsing, …) apply unchanged — see the table in `CLAUDE.md`
at the repo root.  Forward secrecy comes from the freshly-derived
ML-KEM shared secret per handshake; compromise of an ML-DSA-87 long-term
key does not decrypt past sessions.

## History

This started life as a QUIC/ngtcp2 + TLS 1.3 + X.509 client/server pair
(see `README-QUIC.md`).  Phase-36 (2026-05-11) replaced the transport
with MQC, dropping ~700 lines of QUIC plumbing and the entire X.509 +
CRL identity layer.
