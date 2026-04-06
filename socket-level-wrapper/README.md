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

Requires wolfssl-new to be configured and built in the parent directory.

```bash
# Build wolfssl-new first (if not already done)
cd ..
./configure --enable-tls13
make

# Build SLC library and examples
cd socket-level-wrapper
make
```

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

## Dependencies

- wolfSSL (built with `--enable-tls13`)
- POSIX sockets (Linux, macOS, FreeBSD)
- Optional: ECH support (`--enable-ech` in wolfSSL configure)

## Files

```
socket-level-wrapper/
    README.md          This file
    slc.h              Public API (10 functions, 2 types, 1 config struct)
    slc.c              Implementation (~300 lines)
    Makefile           Builds libslc.a + examples
    examples/
        echo_server.c  Demo TLS echo server
        echo_client.c  Demo TLS echo client
        README.md      How to run the examples
```
