# `mqc` — symmetric encrypt/decrypt pipe tool

A small CLI for sealing and opening secrets with a password, shipped
alongside the postWolf CA/leaf kits.  Useful when an operator wants
to tuck a config snippet, API token, or ad-hoc note into source
control or a shared drive without reaching for `openssl enc` or
`age`.

## At a glance

```bash
# Seal (encrypt)
echo 'secret stuff' | mqc --encode --password s3kret > note.mqc.json

# Open (decrypt) — reuses the cached password
cat note.mqc.json | mqc --decode

# File mode with autodetect (JSON envelope → decode, else encode)
mqc --file note.mqc.json
mqc --file /etc/hostname > hostname.mqc.json

# Let the tool pick a strong password
mqc --encode --complex-password --domain team-alpha < secret.txt > secret.mqc.json
# Generated password: <16-char shell-safe string>  ← printed to stderr once
```

## Crypto

| Element | Choice |
|---|---|
| Cipher | **AES-256-GCM** (`wc_AesGcmEncrypt` / `wc_AesGcmDecrypt`) |
| KDF | **scrypt** — `N=32768, r=8, p=1`, 16-byte salt |
| IV | 12 bytes, freshly random per encryption |
| Tag | 16-byte GCM authentication tag |
| Envelope | single-line JSON, hex-encoded byte fields |

Each encryption generates a fresh salt and IV, so re-encrypting the
same plaintext with the same password produces different ciphertexts.
scrypt's parameters are stored in the envelope, so a future bump
doesn't break old ciphertexts.

## Wire format

```json
{
  "v": "mqc-1",
  "tool": "mqc/0.1.0",
  "created": "2026-04-20T19:07:25Z",
  "domain": "factsorlie.com",
  "kdf": "scrypt",
  "N": 32768, "r": 8, "p": 1,
  "salt": "<32 hex chars>",
  "iv":   "<24 hex chars>",
  "ct":   "<ciphertext hex>",
  "tag":  "<32 hex chars>"
}
```

- `v` is the envelope format version.  Anything other than
  `"mqc-1"` is refused with "unsupported mqc format version".
- `tool` identifies the producing binary (e.g. `mqc/0.1.0`).
  Informational; the decoder doesn't validate it — useful when
  debugging mixed-version fleets.
- `created` is the encoding timestamp as an ISO-8601 UTC string
  (`YYYY-MM-DDTHH:MM:SSZ`).  Informational; not used during
  decode but handy for forensic timelines and log correlation.
- `domain` is informational.  On decode with no `--domain`, `mqc`
  uses this field to find the cached password.

## CLI

```
mqc --encode [--password P | --complex-password]
             [--domain D] [--file PATH] [--no-cache]

mqc --decode [--password P] [--domain D] [--file PATH] [--no-cache]

mqc --file PATH [--password P] [--domain D]      # autodetect mode
```

| Flag | Meaning |
|---|---|
| `--encode` | Encrypt (stdin → ciphertext JSON, or `--file` → stdout) |
| `--decode` | Decrypt (JSON → plaintext) |
| `--file PATH` | Read input from `PATH`.  Without `--encode`/`--decode`, autodetects: JSON envelope with `"v":"mqc-1"` → decode; anything else → encode |
| `--out PATH` | Write output to `PATH` (created mode `0600`, truncated if it exists) instead of stdout |
| `--password PW` | Explicit password.  Also writes the cache (unless `--no-cache`) |
| `--complex-password` | Generate a 16-char shell-safe password from `[A-Za-z0-9_-.+=@]` (~97 bits entropy), print it to stderr once, cache, use.  Encode-only |
| `--env` | Read `MQC_MASTER_PASSWORD` from `~/.env` and use it.  Neither reads nor writes the per-domain cache.  Mutually exclusive with `--password` and `--complex-password` |
| `--domain D` | Domain label for cache lookup.  Without it, `~/.TPM/default` symlink resolves |
| `--no-cache` | Skip reading/writing the cache file |
| `-h`, `--help` | Usage |

Output goes to stdout by default, or to `--out PATH` if given.  The
`--out` form creates the file at mode `0600` (safer default for
decoded plaintext) and truncates any existing file.

## Domain + password cache

The cache lives at `~/.TPM/<domain>/mqc-password.pw`, mode `0600`, as
plain text.  `<domain>` is resolved in this order:

1. `--domain D` command-line flag
2. On decode: the `"domain"` field inside the JSON envelope
3. `~/.TPM/default` symlink target's basename

The cache is written whenever `--password` or `--complex-password`
is used (unless `--no-cache`).  Subsequent runs find the cache
automatically — no password flag needed.

Password resolution order:

1. `--password PW`
2. `--env` → `MQC_MASTER_PASSWORD` in `~/.env`
3. Cache file (if present and `--no-cache` not set)
4. Interactive prompt via `/dev/tty` (even if stdin is piped)
5. Hard error with a clear message

## `~/.env` master password (`--env`)

For workflows that want a single master password across every domain
on the host — shell scripts, CI runners, or just "one password I
remember for the box" — `mqc` can pull from `~/.env`:

```bash
$ cat ~/.env
# anything else your shell already sources here is fine
MQC_MASTER_PASSWORD="your-master-password-here"
```

The parser accepts:
- `MQC_MASTER_PASSWORD=value`
- `MQC_MASTER_PASSWORD="value with spaces"`
- `MQC_MASTER_PASSWORD='value'`
- Optional leading `export`
- `#`-prefixed comment lines are ignored; first match wins.

When `--env` is used, `mqc` does not consult or write the per-domain
cache file — `~/.env` is the authority for that invocation.  Keep
`~/.env` `chmod 600` just like you'd keep the cache file.

## `--complex-password` alphabet

The 68-character alphabet is deliberately narrow:

```
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-.+=@
```

No `$`, backtick, backslash, quote marks, `!`, `#`, `*`, `?`, `[`,
`]`, `~`, parentheses, `{`, `}`, `|`, `&`, `;`, `<`, `>`, or space.
Every character is safe bare, single-quoted, and double-quoted in
bash — you can paste the generated password anywhere without
escaping it.

Entropy: 16 × log₂(68) ≈ **97 bits**.

Bias: `mqc` uses rejection sampling on bytes to keep the selection
uniform — no modulo bias.

## Security model

- Passwords at rest on disk.  The cache file is plaintext, mode
  `0600`.  `mqc` is a convenience wrapper, not a secrets manager —
  if the machine is hostile to the `ubuntu` user, the cache is
  readable.  Operators worried about disk compromise should pass
  `--no-cache` and re-type each time.
- GCM auth tag failure on decode surfaces as
  `authentication tag mismatch — wrong password or corrupted
  ciphertext` and exits non-zero.  You cannot distinguish "wrong
  password" from "corrupted ciphertext" — that's a deliberate
  property of AEAD.
- The password in memory is zeroed on exit (`memset` before
  return).  Not pinned, not mlock'd; good enough for operator
  workflow, not a ward against process-memory forensics.
- The tool is Linux-only.  `getpass`-style termios manipulation
  goes through `/dev/tty`; no Windows console support.

## Worked examples

### 1. One-shot encrypt with an explicit password

```bash
$ echo 'api_token=0xdeadbeef' | mqc --encode --password zebra --domain team-alpha
{"v":"mqc-1","domain":"team-alpha","kdf":"scrypt","N":32768,...}
```

Cache file appears:
```bash
$ ls -l ~/.TPM/team-alpha/mqc-password.pw
-rw------- 1 ubuntu ubuntu 6 Apr 20 18:55 /home/ubuntu/.TPM/team-alpha/mqc-password.pw
```

### 2. Decode by feeding the envelope back

```bash
$ cat secret.mqc.json | mqc --decode
api_token=0xdeadbeef
```

No `--password` needed — the cached one is found via the envelope's
`"domain"` field.

### 3. Generate a strong password for a new secret

```bash
$ cat big-secret.txt | mqc --encode --complex-password --domain new-bucket > big-secret.mqc.json
Generated password: KJ478LKOP=2crVSM
(cached at ~/.TPM/new-bucket/mqc-password.pw; save this for offline backup)
```

Copy the printed password into your password manager.  The cache
covers the local machine; the offline backup covers the case where
the disk is lost.

### 4. File mode with autodetect

```bash
# Encrypt a plaintext file
$ mqc --file /etc/hostname > hostname.mqc.json

# Round-trip via autodetect — same command, JSON input flips mode
$ mqc --file hostname.mqc.json
my-host
```

### 5. Interactive decrypt on a fresh machine

```bash
$ cat incoming.mqc.json | mqc --decode --no-cache
Password: ********
the-plaintext
```

Reads the prompt from `/dev/tty`, not stdin — so piping the
ciphertext in doesn't break the prompt.

## Known gaps (tracked TODOs)

- **Streaming huge files** — single-shot encode means RAM is the
  ceiling.  Tracked as TODO #41 (chunked AEAD framing in a future
  `mqc-2` envelope).
- **Rotate / scrub the cache file** — no CLI for password rotation
  or shred-style cache wipe.  Tracked as TODO #42.
- **Cross-host password sync** — the cache is host-local; running
  multiple boxes means copying the file by hand today.  Tracked as
  TODO #43 (push-over-MQC vs pull-from-CA design pending).

## Related

- `socket-level-wrapper-MQC/libmqc.a` — the MQC *library* (ML-KEM /
  ML-DSA network transport) shares a name but is a separate thing.
  They cohabit intentionally: `/usr/local/bin/mqc` is the CLI,
  `/usr/local/lib/libmqc.a` is the transport library.
- `README-bugsandtodo.md` — tracked postWolf TODOs.
