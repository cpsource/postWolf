# SLC Echo Example

Simple echo client/server demonstrating the SLC API.

## Build

```bash
cd socket-level-wrapper
make
```

Requires postWolf to be built in the parent directory first.

## Run

**Terminal 1 — start the server:**
```bash
./examples/echo_server 4433
```

**Terminal 2 — run the client:**
```bash
./examples/echo_client localhost 4433
```

Expected output:

```
# Server
Echo server listening on port 4433
Waiting for connection...
Client connected (fd 4)
Received 10 bytes: Hello SLC!
Client disconnected

# Client
Connecting to localhost:4433...
Connected (fd 3)
Sending: Hello SLC!
Received: Hello SLC!
```

## Certificates

By default, the examples use wolfSSL's test certificates from `../certs/`:
- Server: `server-cert.pem` / `server-key.pem`
- Client: `client-cert.pem` / `client-key.pem`
- CA: `ca-cert.pem`

For production use, replace these with your own certificates.

## What's Happening

1. Server calls `slc_listen` (pure POSIX socket) then `slc_accept` (TLS 1.3 handshake)
2. Client calls `slc_connect` (TCP connect + TLS 1.3 handshake)
3. Both sides use `slc_read`/`slc_write` for encrypted I/O
4. All certificate validation happens inside the API — no security code in the examples
