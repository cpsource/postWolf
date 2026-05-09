# Argon2id reference

Background doc for TODO #79 — switching the `mqc` symmetric envelope's
KDF from scrypt to Argon2id.  Companion to
`README-mqc-tool-hardening-todo-78.md` (which lists the broader
envelope-hardening proposal that #79 is one slice of).

## What it is

Argon2id is a password-hashing / key-derivation function — winner of
the 2015 Password Hashing Competition, standardised in [RFC
9106](https://www.rfc-editor.org/rfc/rfc9106) (September 2021).
The "id" combines two earlier variants:

- **Argon2i** — data-*independent* memory access; resists
  timing-based side-channels.
- **Argon2d** — data-*dependent* memory access; resists time-memory
  tradeoff and parallel-cracking attacks.

Argon2id mixes both: side-channel-safe in the early passes,
GPU-resistant in the later ones.  This is the variant OWASP, NIST
SP 800-63B, and most modern security guidance recommend over the
pure `i` or `d` forms.

## Three knobs

| Parameter | Meaning | Typical range |
|---|---|---|
| `m` (memory cost) | KiB of RAM the derivation requires | 64 MiB → 1 GiB+ |
| `t` (time cost)   | Iterations over the memory block       | 1 – 10           |
| `p` (parallelism) | Independent lanes (lets SMT cores share work) | 1 – 4   |

OWASP's current minimum:  **`m=19 MiB, t=2, p=1`** (target: 1 s on
commodity hardware).
For long-lived at-rest secrets where a few hundred ms is fine:
**`m=256 MiB, t=4, p=1`** (much higher cost for an offline cracker).

## Why over scrypt

`mqc` currently uses **scrypt** with `N=32768, r=8, p=1`.  scrypt is
also memory-hard and not obviously broken, but:

| Concern | scrypt | Argon2id |
|---|---|---|
| RFC standard | none (BSD-licensed paper + reference C) | RFC 9106 |
| Parameter intuition | RAM = `N · r · 128 B` (mental math) | `m` is literally KiB of RAM |
| Side-channel resistance | data-dependent only | hybrid (Argon2i passes are side-channel-safe) |
| GPU resistance | good but parallel attackers amortize | better — proven harder to ASIC-accelerate |
| OWASP / NIST current guidance | "OK if existing" | "preferred for new designs" |
| Implementation maturity | wide | wide; libargon2 is the reference |

For a new system or a flag-day envelope upgrade, Argon2id is the
right call.

## Library options for postWolf

The `mqc` tool is a C example under
`socket-level-wrapper-MQC/examples/mqc.c`.  Three implementation
paths to choose from:

1. **`libargon2`** (`apt install libargon2-dev`) — reference C
   implementation, `argon2_hash` /
   `argon2id_hash_raw` API.  Ships in Debian/Ubuntu, drag-in for
   anything that wants Argon2id.  Lightweight.

2. **wolfCrypt** — postWolf's own crypto layer.  `wc_argon2.h`
   exposes `wc_Argon2_Hash()` and `wc_Argon2`.  Requires building
   wolfSSL with `--enable-argon2`.  Keeps the dependency surface
   inside the wolfSSL family that the rest of postWolf already uses.

3. **OpenSSL 3+** — `EVP_KDF_fetch("ARGON2ID", ...)` via the
   provider API.  Consistent with anything else postWolf already
   uses from OpenSSL.

For consistency with the rest of `mqc.c`'s primitives (which
already pull from wolfCrypt for AES-GCM + the rest of the stack),
**wolfCrypt is the natural pick** — confirm `--enable-argon2` is
on the postWolf build (or add it) and switch.

## Migration shape (for TODO #79)

Single-file change to `socket-level-wrapper-MQC/examples/mqc.c`:

```c
/* Old:
 * scrypt_kdf(password, salt, N, r, p, key);
 */
/* New: */
wc_Argon2_Hash(password, password_len,
               salt, salt_len,
               m_cost_kib, t_cost, p,
               key, key_len);
```

Plus envelope changes (also covered by TODO #78):

```diff
-  "kdf": "scrypt",
-  "N": 32768, "r": 8, "p": 1,
+  "kdf": "argon2id",
+  "kdf_params": { "m": 65536, "t": 3, "p": 1 },
```

Suggested initial parameters: **`m=65536 (64 MiB), t=3, p=1`** —
roughly the same wall-clock cost as the current scrypt settings on
a modern x86_64, with a much clearer parameter story.  Bump `m`
later if profiling shows headroom.

## Deployment / backward compatibility

The envelope already carries a `v` field (`"v": "mqc-1"` today).
Bump to `"v": "mqc-2"` for the Argon2id variant.  Decoder logic
should pivot on `kdf` and `v`:

| `v`     | `kdf`         | Action                                    |
|---------|---------------|-------------------------------------------|
| `mqc-1` | `scrypt`      | Decode legacy blobs (read-only support)   |
| `mqc-2` | `argon2id`    | Encode + decode (default)                 |

Re-encrypt the existing
`server-configuration-data/{env,auth-bundle.tar}.enc.json` blobs as
part of the cutover so the committed at-rest data uses the stronger
KDF too.

## Verification

After the swap:

```sh
# Encode + decode round-trip.
echo "smoke" | mqc --encode --password test > /tmp/blob.json
mqc --decode --password test --file /tmp/blob.json | grep -q '^smoke$' \
    && echo "ROUND-TRIP OK"

# Confirm envelope version + KDF.
jq '.v, .kdf, .kdf_params' /tmp/blob.json
# Expect:
#   "mqc-2"
#   "argon2id"
#   { "m": 65536, "t": 3, "p": 1 }

# Confirm the decoder still reads legacy mqc-1 blobs.
mqc --decode --password $OLD_PW --file env.enc.json   # the existing committed blob
```

## See also

- `README-mqc-tool-hardening-todo-78.md` — the full external review
  that prompted this change; KDF cost is item #3 of six.
- RFC 9106 — Argon2 specification.
- OWASP password storage cheatsheet —
  <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
