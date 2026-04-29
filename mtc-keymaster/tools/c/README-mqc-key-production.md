# How `MQC_MASTER_PASSWORD` becomes the AES-256-GCM key

This document traces the path inside the `mqc` CLI binary
(`mtc-keymaster/tools/c/mqc.c`) from the `MQC_MASTER_PASSWORD` value
in `~/.env` to the actual 32-byte key used by AES-256-GCM.

## Stage 1 — read the env-file value verbatim

`tools/c/mqc.c:513` (`read_env_password`) opens `~/.env`, finds the
first non-comment line matching `MQC_MASTER_PASSWORD=...` (an optional
`export` prefix and `'...'` / `"..."` quoting are tolerated), trims
whitespace/quotes, and copies the raw bytes into a stack buffer
(`pw_out`, capped at `MQC_PW_MAX=512`). No transformation — what's in
the file *is* the password string.

That string then flows into `main()` at `mqc.c:960` and ultimately to
`encode_blob` / `decode_blob` as `const char *password`.

## Stage 2 — scrypt-derive the AES-256 key

The actual encryption key is produced inside `derive_key` at
`mqc.c:156`:

```c
wc_scrypt(key_out,
          (const byte *)password, (word32)strlen(password),
          salt, salt_sz,
          MQC_KDF_LOG2N, MQC_KDF_R, MQC_KDF_P,
          MQC_AES_KEY_SZ);
```

Parameters from the `#define`s at `mqc.c:59-66`:

| Param   | Value           | Meaning                                  |
|---------|-----------------|------------------------------------------|
| log2(N) | 15 (N = 32768)  | scrypt cost                              |
| r       | 8               | block size                               |
| p       | 1               | parallelism                              |
| salt    | 16 random bytes | freshly RNG'd per encode (`mqc.c:192`)   |
| dkLen   | 32              | AES-256 key length                       |

Salt is fresh per encode and stored in the JSON envelope; on decode
(`mqc.c:369`) the same `wc_scrypt` is run with the salt parsed back
out, regenerating the same 32-byte key.

## Stage 3 — AES-256-GCM seal

`mqc.c:208` does `wc_AesGcmSetKey(&aes, key, 32)` and then
`wc_AesGcmEncrypt` with a fresh 12-byte IV (`mqc.c:218`). The 16-byte
GCM tag, IV, salt, and ciphertext go into the JSON envelope; the
32-byte key is `memset`-zeroed at `mqc.c:276`.

## Summary

```
~/.env line "MQC_MASTER_PASSWORD=..."  (literal bytes, <=512 chars)
                |
                v  (read_env_password -- verbatim, no hashing)
        password string in memory
                |  (+ random 16-byte salt per encode)
                v  (derive_key -> wc_scrypt N=32768, r=8, p=1)
        32-byte AES-256 key
                |  (+ random 12-byte IV)
                v  (wc_AesGcmEncrypt)
        ciphertext + 16-byte GCM tag in JSON envelope
```

So `MQC_MASTER_PASSWORD` is treated as a UTF-8 password (not a hex
key), and the only transformation between the env file and the AES
key is a single scrypt(N=32768, r=8, p=1, salt=16 random bytes) ->
32-byte output.
