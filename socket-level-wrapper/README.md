# Socket Level Connection (SLC) API

A simplified wrapper over wolfSSL that provides TLS 1.3 + ECH + MTC
(Merkle Tree Certificate) connections through a familiar socket-like API.

## Design Principle

**No security goo pushed to the caller.** All authentication, certificate
validation, Merkle proof verification, ECH negotiation, and revocation
checking happen inside the API. The caller gets back a fully authenticated
connection or NULL — nothing in between.

```c
conn = slc_connect(ctx, "factsorlie.com", 8080);
if (conn == NULL) {
    /* connection failed or authentication failed — same thing */
}
/* conn is fully authenticated — safe to read/write */
```

## API at a Glance

| Function | Purpose |
|----------|---------|
| `slc_ctx_new(cfg)` | Create TLS 1.3 context from config struct |
| `slc_ctx_set_mtc(ctx, server, key, sz)` | Enable MTC verification (optional) |
| `slc_ctx_free(ctx)` | Free context |
| `slc_connect(ctx, host, port)` | TCP connect + TLS handshake (client) |
| `slc_listen(host, port)` | Bind + listen (pure POSIX, no TLS) |
| `slc_accept(ctx, listen_fd)` | Accept + TLS handshake (server) |
| `slc_read(conn, buf, sz)` | Read decrypted data |
| `slc_write(conn, buf, sz)` | Write encrypted data |
| `slc_close(conn)` | Shutdown TLS + close socket |
| `slc_get_fd(conn)` | Get raw fd for select/poll |

## Call Flow

```
ctx = slc_ctx_new(&cfg)              create once, configure
slc_ctx_set_mtc(ctx, ...)            optional MTC config
  |
  |-- slc_connect(ctx, host, port) -> conn     (client)
  |     +-- slc_read/write(conn)
  |     +-- slc_close(conn)
  |
  |-- fd = slc_listen(host, port)              (server, no ctx needed)
  |     +-- slc_accept(ctx, fd) -> conn        (server)
  |           +-- slc_read/write(conn)
  |           +-- slc_close(conn)
  |
  +-- slc_ctx_free(ctx)              done
```

## What Happens Inside slc_connect / slc_accept

When these functions return a non-NULL connection, all of the following
have succeeded:

- TCP socket connected / accepted
- TLS 1.3 handshake completed
- Peer certificate chain validated
- ECH negotiated (if configured)
- MTC leaf index auto-discovered from loaded cert (if configured)
- Merkle inclusion proof retrieved and replayed (if configured)
- Ed25519 cosignature verified against pinned CA key (if configured)
- Revocation status checked (if MTC server reachable)

If ANY step fails, the connection is torn down and NULL is returned.

## Building

Requires postWolf to be configured and built in the parent directory.
From a fresh checkout, the top-level driver does everything:

```bash
cd ..
./make-all.sh        # library + SLC + MQC + QUIC + MTC tools
```

To rebuild only SLC (library already present):

```bash
cd socket-level-wrapper
make                 # produces libslc.a + examples/echo_{server,client}
```

Note that SLC links against the in-tree `../src/.libs/libpostWolf.so`
(with rpath), so it does *not* require `sudo make install` of the
library — unlike MQC, QUIC, and the MTC tools, which resolve postWolf
through `pkg-config`.

This produces:
- `libslc.a` — static library
- `examples/echo_server` — demo TLS echo server
- `examples/echo_client` — demo TLS echo client

## Quick Test

```bash
# Terminal 1
./examples/echo_server 4433

# Terminal 2
./examples/echo_client localhost 4433
```

See `examples/README.md` for details.

## Configuration

### Basic TLS (no MTC)

```c
slc_cfg_t cfg = {
    .role      = SLC_CLIENT,
    .cert_file = "client.pem",
    .key_file  = "client-key.pem",
    .ca_file   = "ca-cert.pem",
};
slc_ctx_t *ctx = slc_ctx_new(&cfg);
```

### With ECH

```c
slc_cfg_t cfg = {
    .role            = SLC_CLIENT,
    .cert_file       = "client.pem",
    .key_file        = "client-key.pem",
    .ca_file         = "ca-cert.pem",
    .ech_configs_b64 = "AEX+DQB...",  /* base64 ECH config */
};
```

### With MTC

```c
slc_ctx_t *ctx = slc_ctx_new(&cfg);
slc_ctx_set_mtc(ctx, "factsorlie.com", ca_pubkey, 32);
```

The MTC leaf index is auto-discovered from the loaded certificate —
the caller never needs to look it up.

## wolfSSL Include Order and Build Flags

wolfSSL requires `wolfssl/options.h` to be included before any other wolfSSL
headers. The SLC implementation handles this internally — callers that only
include `slc.h` do not need to worry about it.

If your application includes wolfSSL headers directly alongside `slc.h`,
either include `wolfssl/options.h` first or compile with
`-DWOLFSSL_USE_OPTIONS_H`.

### How the Makefile picks up feature flags

wolfSSL stores its compile-time feature macros (`WOLFSSL_TLS13`, `HAVE_ECH`,
`HAVE_MTC`, `HAVE_TRUST_ANCHOR_IDS`, etc.) in `AM_CFLAGS` in the top-level
Makefile — not in `wolfssl/options.h`. The SLC Makefile extracts these flags
automatically so that SLC code compiles with the same feature set as the
library:

```makefile
WOLFSSL_CFLAGS := $(filter-out $$(EXTRA_CFLAGS), \
    $(shell sed -n 's/^AM_CFLAGS = //p' $(WOLFSSL_DIR)/Makefile))
```

This means SLC will automatically see `HAVE_ECH`, `HAVE_TRUST_ANCHOR_IDS`,
`HAVE_MTC`, `WOLFSSL_TLS13`, and all other flags the library was built with.

## Trust Anchor IDs

When MTC is configured via `slc_ctx_set_mtc()`, the SLC library automatically
registers the MTC CA public key as a **Trust Anchor ID** (draft-ietf-tls-trust-anchor-ids).

Trust Anchor IDs let a TLS client tell the server which root CAs it trusts.
This is critical for MTC: the server needs to know the client supports MTC
verification so it can send an MTC certificate chain (with Merkle proof)
instead of a traditional X.509 chain.

The SLC library:
1. Hashes the CA public key with SHA-256
2. Registers the hash as a trust anchor ID via `wolfSSL_CTX_UseTrustAnchorId()`
3. The trust anchor ID is included in the ClientHello `trust_anchors` extension

The caller never touches trust anchor IDs directly — it's handled inside
`slc_ctx_set_mtc()`.

## Dependencies

- wolfSSL (built with `./configure.sh` — enables TLS 1.3, ECH, MTC, DTLS 1.3)
- POSIX sockets (Linux, macOS, FreeBSD)
- ECH: `--enable-ech` in wolfSSL configure (included in `configure.sh`)
- MTC: `--enable-mtc` in wolfSSL configure (included in `configure.sh`)

## Files

```
socket-level-wrapper/
    README.md          This file
    slc.h              Public API (10 functions, 2 types, 1 config struct)
    slc.c              Implementation (~500 lines)
    Makefile           Builds libslc.a + examples
    examples/
        echo_server.c  Demo TLS echo server
        echo_client.c  Demo TLS echo client
        README.md      How to run the examples
```
