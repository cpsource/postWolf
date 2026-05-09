# Takeaway lessons

Three lessons from comparing our hand-crafted `src/ssl_load.c` review
to the upstream fix that landed as
[wolfSSL PR #10168](https://github.com/wolfSSL/wolfssl/pull/10168).
Our diagnosis matched upstream byte-for-byte on 5 of 6 findings, and
we could have been 6/6 if the three traps below had been avoided.

The skill's Phase 11 checklist forces each of these to be answered
before committing.

---

## 1. Don't punt on "latent-only" bugs with small fixes

The ssl_load.c review flagged a cast-away-const pattern on a DER
buffer at `src/ssl_load.c:5937` as "latent only — no functional impact
and would require a broader DerBuffer API change to fix properly,"
and we skipped it.

Upstream fixed it in three lines: change `AllocDer(&der, 0, ...)` to
`AllocDer(&der, sz, ...)` and replace the pointer assignment with
`XMEMCPY(der->buffer, buf, sz)`. No API change.

**How this applies**: Before classifying a finding as "skip-latent",
count the lines needed to fix it. If it's ≤3 lines of change
touching only the offending function, fix it. "Broader API change"
is only true if the fix leaks into the caller's signature or
disturbs at least one other translation unit. Otherwise it's a cheap
win sitting on the table.

The skill asks this explicitly:

> **Latent bugs**: Did I flag anything as "latent only, skip"?
> Re-check whether the fix is really >3 lines. If ≤3 lines, fix it.

---

## 2. When functions have zero test coverage, add regression tests

The ssl_load.c review noted — in its "Tests missing" section — that
`wolfSSL_add1_chain_cert`, `wolfSSL_use_AltPrivateKey_Id`,
`wolfSSL_use_AltPrivateKey_Label`, and `wolfSSL_CTX_set_tmp_dh`
(via a DH object) had no existing test coverage. We named the gap but
did not close it.

Upstream's PR added the tests we should have added. Their
`test_wolfSSL_CTX_add1_chain_cert` addition is exemplary: after
calling `add1`, it asserts `wolfSSL_RefCur(x509->ref) == 2`. That
specific assertion would have caught the original `==` vs `=` bug
directly — the pre-fix code happened to return 1 (pass) while
leaving the refcount at 1 (the bug). Without the concrete numeric
assertion, the buggy code looks fine.

**How this applies**: When the fix touches a function with zero
coverage, the C reproducer (or a tests/ addition) must include at
least one assertion on a *concrete value that differs between the
bug and the fix* — not just a non-nil or non-zero check.

- For refcount bugs: assert the exact post-op refcount.
- For length/size bugs: assert the exact byte count.
- For encoding bugs: `memcmp` against a known-good byte string.
- For state bugs: derive a handshake key and decrypt a record
  (as issue-10287 does).

The skill asks this explicitly:

> **Zero-coverage functions**: Do the functions I touched have any
> existing tests? If no, add at least one assertion in my C test (or
> a test case in the tests/ directory) that would have caught the
> specific bug I'm fixing. Concrete value checks, not just
> non-nil / non-zero.

---

## 3. Trust the diagnostic output; chase the wire-level symptom

Across #10019, #10271, #10287, and the ssl_load.c review, the bug
diagnosis was consistently strong — byte-for-byte match with the
maintainer's edits on five independent locations in ssl_load.c,
without having seen the upstream PR. That's a strong signal the
review process itself works.

The trap is stopping one level short of the wire. For issue #10287
the initial reproducer showed the server accepted a
multi-key-share ClientHello and sent back a ServerHello — we
reported "bug reproduced". It wasn't, in the useful sense:
the visible ServerHello looked normal; the bug is that the server's
subsequent encrypted record is un-decryptable because `preMasterSecret`
was clobbered. The real reproducer runs the client-side key schedule
and attempts AEAD decrypt.

**How this applies**: A diagnosis is only complete when there's an
unbroken causal chain from the source-level defect to the user-
observable symptom reported in the issue. If the issue says
"handshake fails with X", the reproducer must show X, not just
"server accepts something weird".

The skill asks this explicitly:

> **Wire-level trace**: Does the diagnosis connect the code defect
> to the user-visible symptom in the issue? If I can only say "this
> variable is wrong", keep tracing.

---

## Using the checklist

Phase 11 of `SKILL.md` makes these three questions blocking. Answer
each before committing:

- [ ] Question 1: Latent findings reconsidered?
- [ ] Question 2: Zero-coverage functions closed with a concrete-
      value test?
- [ ] Question 3: Diagnosis traced to the wire-level symptom?

"Considered and rejected because X" is an acceptable answer. Skipping
the question is not.
