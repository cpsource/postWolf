# qsh / qshd — slash-command specifications

This document specifies the file-transfer slash commands `/get` and
`/put` that qsh and qshd support on top of the existing MQC-framed
shell session.  It supplements the protocol comment at the top of
both `qsh.c` and `qshd.c`.

## 1.  Wire-format additions

The base frame layout from the shell protocol is unchanged:

```
byte 0   type
bytes 1+ payload
```

Two new frame types are added:

| Type | Name             | Direction | Payload                                            |
|------|------------------|-----------|----------------------------------------------------|
| 0x05 | `FRAME_CMD_REQ`  | C → S     | `"/get\n"` *or* `"/put\n"` then a single JSON obj. |
| 0x06 | `FRAME_CMD_RESP` | S → C     | Single JSON object (success or error).             |

Both peers exchange exactly **one** frame per logical operation:

```
qsh   ──FRAME_CMD_REQ─►  qshd       (verb + JSON request body)
qsh  ◄──FRAME_CMD_RESP──  qshd      (JSON response body)
```

There is no chunking, no continuation, no streaming.  A single MQC
message carries the whole transfer.  The MQC stack caps a single
message at `MQC_MAX_MSG = 1 MiB`, which after JSON framing and hex
expansion (`2×`) gives a hard ceiling of ~256 KiB of raw file data
per transfer.  Files that exceed this cap are rejected with an
`error` response — no half-transfers, no resume.

`FRAME_DATA` frames may interleave with `FRAME_CMD_REQ` /
`FRAME_CMD_RESP` while the request is in flight (the remote PTY
keeps producing output).  Frames are demultiplexed by the type byte.

## 2.  JSON envelope

All five fields are present in both directions on the data-carrying
side of the exchange (response for `/get`, request for `/put`).

| Field         | Type   | Meaning                                                        |
|---------------|--------|----------------------------------------------------------------|
| `from`        | string | Remote-side absolute or relative path (`/get` only).           |
| `to`          | string | Remote-side absolute or relative path (`/put` only).           |
| `compressed`  | bool   | Whether `data` is zlib-compressed.  Default `true`.            |
| `protection`  | string | 10-char `ls -l` style mode, e.g. `-rw-r--r--` or `drwxr-xr-x`. |
| `byte_count`  | int    | Number of **raw** (uncompressed) bytes the payload represents. |
| `data`        | string | Hex (lowercase) encoding of the file bytes (compressed or not).|

Failure replies omit everything except `error`:

| Field   | Type   | Meaning                                                       |
|---------|--------|---------------------------------------------------------------|
| `error` | string | Operator-readable failure message (e.g. `"open: No such ..."`). |

`error` is the sole failure indicator: success replies do not set it,
failure replies set nothing else.

### Hex encoding

`data` is the lowercase hex of the raw byte sequence — two hex
characters per byte, no separators, no `0x` prefix, no newlines.
Decoding is endian-free by construction (each byte stands alone),
which is the entire reason we chose hex over a binary format on a
JSON wire.

### Compression

When `compressed` is `true`, `data` is the hex of a **zlib deflate
stream** (`Z_DEFAULT_COMPRESSION`) of the raw bytes.  The receiver
inflates to recover `byte_count` raw bytes.  When `compressed` is
`false`, `data` is the hex of the raw bytes directly.  The
**default on both sides is `compressed: true`**; clients only set
`false` for files known to be incompressible (already-gzipped,
encrypted, etc.).

### Protection

`protection` is the 10-character mode string returned by `ls -l`
— the same layout as `stat -c '%A'` produces:

```
-rwxr-xr-x      regular file
drwxr-xr-x      directory
lrwxrwxrwx      symlink
-rw-rw-r--      etc.
```

On `/get` the server reports the current mode of the file it
sends.  On `/put` the client tells the server what mode to apply
to the newly-written file.  The leading type character is
informational only: `/put` always writes a **regular file**.
Only the trailing nine bits are honoured via `chmod()`.

Symlinks, devices, sockets, and directories are not transferable
in v1 — the server rejects them with an `error`.

## 3.  `/get` semantics

CLI on the qsh client:

```
/get <remote-from> <local-to>
```

The client sends:

```
FRAME_CMD_REQ payload:
/get
{"from":"<remote-from>","compressed":true}
```

The server reads `<remote-from>` with the privileges of the
forked shell child (the same uid that runs the user's bash).
If it cannot `open()` for read, cannot `stat()`, the file is
not a regular file, or the file exceeds the size cap, the
server replies with `{"error":"..."}`.

On success the server replies:

```
FRAME_CMD_RESP payload:
{
  "from":        "<remote-from>",
  "compressed":  true,
  "protection":  "-rw-r--r--",
  "byte_count":  12345,
  "data":        "<hex>"
}
```

The client decodes `data` (inflating if `compressed:true`),
verifies the resulting byte length matches `byte_count`, writes
the bytes to `<local-to>` with `O_CREAT|O_TRUNC|O_WRONLY`, and
applies the low nine bits of `protection` via `fchmod()`.  If
the local-side write fails, the client prints an error to its
own stderr; the server is not informed.

## 4.  `/put` semantics

CLI on the qsh client:

```
/put <local-from> <remote-to>
```

The client reads `<local-from>` from the local filesystem, stats
it for mode bits, optionally zlib-compresses the bytes, hex-encodes
the result, and sends:

```
FRAME_CMD_REQ payload:
/put
{
  "to":          "<remote-to>",
  "compressed":  true,
  "protection":  "-rw-r--r--",
  "byte_count":  12345,
  "data":        "<hex>"
}
```

The server validates the JSON, decodes `data` (inflating if needed),
checks the decoded byte length matches `byte_count`, writes the
bytes to `<remote-to>` with `O_CREAT|O_TRUNC|O_WRONLY`, and applies
the low nine bits of `protection` via `fchmod()`.

On success the server replies with the count of bytes actually
written:

```
FRAME_CMD_RESP payload:
{"to":"<remote-to>","byte_count":12345}
```

On any failure (open, write, mode parse, size cap, malformed
JSON) the server replies with `{"error":"..."}` and the partial
file — if any — is removed before the response goes out.

## 5.  Client UX

qsh runs the local terminal in raw mode; every keystroke is normally
forwarded to the remote PTY.  Slash-command interception only fires
when **the user's first character on a fresh input line is `/`**:

- `at_line_start` is true on connect and after every `\r` or `\n`
  the user types.  It is set false by any other typed byte.
- When `at_line_start && c == '/'`, qsh enters "command-buffer"
  mode: subsequent keystrokes are echoed locally and accumulated
  in a 256-byte buffer instead of forwarded.  Backspace (`\x7f`
  or `\x08`) edits the buffer.  Ctrl-C cancels the buffer.
- When the user types Enter, qsh parses the buffer:
  - `/get <remote-from> <local-to>` → build request, send, await
    response, write local file.
  - `/put <local-from> <remote-to>` → read local file, build
    request, send, await response, print status.
  - anything else (e.g. `/etc/foo`) → print a local error line,
    do not forward.

Lines that don't start with `/` are forwarded byte-by-byte exactly
as before.  To type a path that starts with `/` at a shell prompt,
prefix with a space (`␣/etc/foo`); the space is not `/`, so qsh
forwards it normally and bash trims/handles it as usual.

The client awaits `FRAME_CMD_RESP` synchronously but keeps reading
incoming MQC frames so `FRAME_DATA` (PTY output produced while the
command is in flight) continues to render.  Only `FRAME_CMD_RESP`
completes the slash command; out-of-band `FRAME_DATA` is treated
identically to normal interactive output.

## 6.  Server UX

qshd's session-loop branch on the frame type:

- `FRAME_DATA`     → write to PTY (unchanged)
- `FRAME_RESIZE`   → TIOCSWINSZ (unchanged)
- `FRAME_OPEN_SHELL` → first-frame-only (unchanged)
- `FRAME_CMD_REQ`  → split at the first newline; verb must be
  exactly `/get` or `/put`; parse JSON body strictly via json-c;
  perform the operation; emit `FRAME_CMD_RESP`.

The command is handled in the same forked child that owns the
PTY, so file accesses use the bash account's credentials.  The
PTY is not paused — output continues to drain to MQC as usual,
giving the user a coherent terminal view if the file op runs
slowly.

## 7.  Limits

| Limit                                   | Value          |
|-----------------------------------------|----------------|
| Max raw bytes per `/get` or `/put`      | 262 144 (256 KiB) |
| Max hex-encoded JSON envelope            | 1 048 576 (`MQC_MAX_MSG`) |
| Max command-buffer length on the client  | 256 bytes      |
| Max `from`/`to` path length              | 4096 bytes (`PATH_MAX`) |

Hitting any of these is a flat error — no fallback, no chunking.

## 8.  Security posture

- The server only acts on a `FRAME_CMD_REQ` *after* the same MQC
  handshake that authorises the shell — that is, ML-KEM-768 +
  ML-DSA-87 + Merkle inclusion + cosignature + revocation check
  + the cert-index ACL in `/etc/qsh/qshd/config`.  A peer that
  cannot open a shell cannot transfer files either.
- File operations run as the session's effective uid — the same
  user the bash login shell runs as.  There is no privilege
  escalation surface; if the operator did not start qshd with
  `--user`, the operations run as whatever account systemd's
  `User=` set.
- The 256 KiB cap and the 1 MiB MQC cap together bound the
  per-message memory budget on both sides.  Compression is
  inflated into a `byte_count`-sized buffer the server allocates
  *after* checking `byte_count` against the cap, so a malicious
  client cannot zip-bomb the server.
- Path traversal is the operator's responsibility: the server
  does not chroot or sandbox.  If `/etc/qsh/qshd/config` lets a
  peer in, that peer's `/get` and `/put` can reach anything the
  unix user can.

## 9.  Out of scope

- Streaming / resumable transfers.
- Directory transfer (`-r`).
- Symlink preservation.
- Owner / group preservation (`chown` requires root).
- Atomic rename — the server `open(O_TRUNC)`s the destination
  directly.  Operators who need atomic replacement should `/put`
  to a sidecar name and `mv` it from the shell.
- Server-side checksum / integrity proof beyond what MQC already
  provides (AEAD AAD over every frame).  An attacker who flipped a
  byte in transit would have failed the AES-GCM tag check and
  killed the session before any `data` was decoded.
