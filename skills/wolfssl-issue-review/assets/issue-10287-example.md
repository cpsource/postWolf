# Worked example: issue #10287

The canonical reference for what this skill produces. Issue #10287 —
"Handshake failure when ClientHello contains multiple PQC/hybrid
key shares" — was the template the skill was built from. Re-read
these files when unsure what "a good review looks like".

The files below live in the author's wolfSSL tree at
`/home/ubuntu/wolfssl/issue-10287/`, and are also visible on GitHub
at the wolfSSL issue thread:
<https://github.com/wolfSSL/wolfssl/issues/10287>.

## Guided tour

### `README-issue-10287.md`

10 H2 sections in the order the template prescribes. Worth reading
top to bottom at least once:

- `## The bug` — enumerates the two observable failure modes
  (hybrid-first vs pure-first) and the exact error code / log
  line for each.
- `## Upstream status` — shows the format for the `gh pr list` +
  `gh search issues` + keyword-search summary. This section is
  defensive: it proves the work wasn't redundant.
- `## Root cause` — split into four sub-sections walking the code
  path: eager encap during parse, shared-state clobber, selection
  happens afterwards, concrete failure modes. Each sub-section
  quotes `src/tls.c:LINE` and the offending code block.
- `## Why the current design exists` — quotes the comment in the
  code explaining the memory optimisation that painted the design
  into a corner. Don't skip this when the bug is an artefact of a
  design choice.
- `## Proposed fix` — three numbered touch-points. Ends with an
  "After the fix:" paragraph enumerating the new invariants.
- `## Caveats and risks` — four bullets covering memory, build
  guards, stateless parse, and HelloRetryRequest.
- `## Tests to add` — three specific test descriptions.
- `## Files touched by the proposed patch` — one-liner.
- `## Appendix — end-to-end verification` — 8 numbered steps
  describing exactly what the C reproducer does, followed by the
  observed 2×2 BEFORE/AFTER results table.
- `## Running the test harness` — how to invoke `test.sh`, expected
  abbreviated output, exit-code semantics.

### `issue-10287.patch`

147-line unified diff against `src/tls.c`. Three functions:

- `TLSX_KeyShareEntry_Parse` — drops the
  `ke = (byte*)&input[offset]` eager shortcut; always malloc-and-
  copies.
- `TLSX_KeyShare_Use` — removes the eager PQC/hybrid dispatch
  block.
- `TLSX_KeyShare_Setup` — runs the PQC/hybrid encap handler there
  instead, for whichever group `TLSX_KeyShare_Choose` picked.

Patch has inline comments including the string `issue #10287` so
`test.sh` can detect patched vs unpatched state.

### `issue-10287-test.c`

~750 lines, self-contained. Links against `-lwolfssl` only. Does
the full TLS 1.3 client side:

- **Ephemeral key gen** — one P-384 keypair, two independent
  ML-KEM 1024 keypairs; private halves are retained for later
  decap/ECDH.
- **ClientHello construction** — hand-built byte buffer; forces
  `TLS_AES_128_GCM_SHA256` (0x1301) so the rest of the key schedule
  is fixed-form.
- **Send + parse** — plain TCP to `localhost:11111`; parse
  ServerHello to extract chosen group + server's key_exchange
  payload.
- **Shared secret** — `KEM-Decap` only (pure group) or
  `ECDH || KEM-Decap` (hybrid).
- **RFC 8446 §7.1 key schedule** — `early_secret → derived →
  handshake_secret → s_hs_traffic → server_key + server_iv` via
  `wc_Tls13_HKDF_Extract` / `wc_Tls13_HKDF_Expand_Label`.
- **AEAD decrypt** — `AES-128-GCM` on the server's first AppData
  record. PASS iff tag verifies and the plaintext starts with
  `0x08` (EncryptedExtensions handshake type).

Lessons encoded in this reproducer:

1. The test does *not* stop at "server sent a ServerHello". It
   keeps going until it decrypts an actual encrypted record — the
   wire-level symptom the user reports.
2. The test's PASS/FAIL criteria are concrete values
   (tag verification succeeds, `plain[0] == 0x08`), not "no
   error returned".

### `test.sh`

180 lines. Start-to-finish automation. The
`references/test-sh-template.sh` in this skill is a parameterised
version of exactly this file.

Execution on a clean tree:

```
Overall: all four outcomes as expected.
```

exit 0.

## When to deviate from this example

- Different bug surface — not every bug needs TCP + key schedule.
  Issue #10019's reproducer was a pure-wolfCrypt encode/decode
  round-trip, ~150 lines. Issue #10271 was smaller still — just
  `configure` + `make` exercising a new flag. Scale the reproducer
  to the bug.

- No reproducer feasible — some wolfSSL bugs are build-system
  only, or require specific hardware (crypto callbacks, secure
  elements). In those cases, skip `issue-N-test.c`, skip the
  `Appendix — end-to-end verification` section of the README, and
  have `test.sh` run `make check` on the relevant test names
  instead.

## Reference

The commit that introduced these files to the author's tree:
`02e47cfa1 issue-10287: reproducer, patch, and BEFORE/AFTER test harness`

The GitHub reply assembled from them:
<https://github.com/wolfSSL/wolfssl/issues/10287#issuecomment-4304463680>
