I inspected the **8445 CA registration path**. DNSSEC addition is a big improvement, but I see several flaws.

> **Status (2026-05-04): all six items DONE.**  Each section
> below is annotated with the closing commit; the in-tree
> source is now consistent with the prescribed fixes.  See the
> per-issue commit messages for design rationale and live-
> verification notes.

## Serious issues

### 1. Public-key cross-check is broken — **DONE 2026-05-04 (commit `d5a8779bb`)**

In `mtc_ca_validate.c`, the CA cert fingerprint is:

```c
SHA3-256(SPKI DER)
```

But in `mtc_bootstrap.c`, the submitted `public_key_pem` is checked as:

```c
SHA-256(public_key_pem text)
```

Those will not match.

So this block is wrong:

```c
wc_Sha256Update(&sha_pk, (const uint8_t *)pub_key_pem,
                (word32)strlen(pub_key_pem));
```

Fix: parse `public_key_pem`, extract canonical SPKI DER, then compute:

```text
SHA3-256(SPKI DER)
```

and compare to `x509_spki_fp`.

---

### 2. CA revocation gate appears broken — **DONE 2026-05-04 (commit `6ca6f65c2`)**

You already require CA subject:

```text
<SAN>-ca
```

Example:

```text
foobar.com-ca
```

But the revocation gate does this:

```c
snprintf(ca_subject, sizeof(ca_subject), "%s-ca", subject);
```

So it searches for:

```text
foobar.com-ca-ca
```

That means revoked CA entries probably will not block re-enrollment.

Fix:

```c
snprintf(ca_subject, sizeof(ca_subject), "%s", subject);
```

---

### 3. DNSSEC TXT validation is too loose — **DONE 2026-05-04 (commit `bdbf08309`)**

Right now `mqc_dnssec_validate_ca_kh()` accepts any DNSSEC-secure TXT token containing:

```text
kh=sha3-256:<expected>
```

It does **not require**:

```text
v=MQC1
role=ca
alg=ML-DSA-87
```

That means an unrelated secure TXT record with the same `kh=` token could authorize enrollment.

Fix: parse the TXT as a full MQC record and require:

```text
v == MQC1
role == ca
alg == expected CA key algorithm
kh == expected hash
```

---

## Medium issues

### 4. CA X.509 cert is parsed with `NO_VERIFY` — **DONE 2026-05-04 (commit `c84de74bf`, doc-only)**

This is acceptable only if your real trust anchor is DNSSEC pinning of the SPKI. But then the cert is mostly a structured container, not a real X.509 trust object.

I would explicitly treat it that way in comments/spec:

```text
The CA cert signature chain is not trusted. DNSSEC-pinned SPKI is the authority.
```

Or verify it is self-signed by the same SPKI.

---

### 5. No proof-of-possession for CA private key — **DONE 2026-05-04 (commit `308560ae4`)**

DNSSEC proves the domain published the public-key hash. It does not prove the requester controls the private key.

Add a challenge:

```text
server_nonce = random
client signs: MQC-CA-REGISTER|domain|subject|spki_hash|server_nonce
server verifies with submitted CA public key
```

This prevents registering a CA key the requester cannot actually use.

---

### 6. Domain/SAN normalization is missing — **DONE 2026-05-04 (commits `825e75a88` server-side + `1dd96b286` client-side gate)**

Before comparing or querying DNS, normalize and reject weird names:

Reject:

```text
*.example.com
example.com.
_mqc-ca.example.com
invalid chars
```

Normalize:

```text
lowercase
strip trailing dot if allowed
IDNA/punycode consistently
```

---

## Good things I saw

* DNSSEC fails closed on bogus or insecure zones.
* CA subject is tied to SAN via `<SAN>-ca`.
* CA enrollment does not rely on leaf nonce.
* Leaf and CA paths are separated.
* There is rate limiting on bootstrap enrollment.
* 8445 encrypted enrollment payload is length-prefixed after DH.

## Biggest fixes to do first

1. Fix the CA public-key hash comparison: **SHA3-256 over SPKI DER**, not SHA-256 over PEM text.
2. Fix the revoked CA lookup: do **not append `-ca` twice**.
3. Require full TXT schema fields, not just `kh=`.
4. Add CA proof-of-possession signature over a server nonce.

