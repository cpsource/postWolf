> **Reading order.** This file is the DNSSEC-bootstrap design
> exchange (~900 lines, four trust-bootstrap options + a
> drop-in `mqc_dnssec_pin.c`).  For the current "what is still
> open?" scoreboard, see
> [`../README-mqc-issues-summary.md`](../README-mqc-issues-summary.md);
> the DNSSEC pin shipped via `bf21e4fc9` and `bdbf08309`.

Good—this extra detail helps a lot. I’ll map everything explicitly to your ports and give concrete fixes you can actually implement without killing your “open developer CA” goal.

---

# 🧭 Your architecture (clarified)

* **8445 → `url-bootstrap` (public, weak trust)**

  * Fetch CA pubkey
  * Register CA / Leaf
  * TOFU happens here (problem area)

* **8446 → `url-server` (MQC secure channel)**

  * Post-handshake encrypted traffic
  * Should be *fully locked down*

* **8444 → internal**

  * Not relevant to external threat model

---

# 🔴 Where the real risk is

👉 The vulnerability I called out is **100% on port 8445 (bootstrap)**

NOT 8446.

Once a bad key is accepted via 8445, **8446 becomes securely encrypted… with the attacker**.

---

# ⚠️ What TOFU is doing to you

Your current model:

```text
Client → 8445 → fetch CA key → cache → trust forever
```

Problem:

* First connection can be MITM’d
* Attacker injects fake CA
* You permanently trust attacker

👉 Everything after that (even MQC) is compromised

---

# 🧠 Your constraint (important)

You said:

> “I want dev groups to create their own CA’s with minimal to none exchange with me”

So:

* ❌ No central CA approval
* ❌ No manual key distribution
* ✔ Must be self-service

That rules out simple pinning.

---

# ✅ Best-fit solution for your model

You already *almost* have the right idea:

👉 **Use DNS as the root of trust—but make it cryptographic**

---

# 🔐 Fix for 8445 (bootstrap port)

## Option 1 (RECOMMENDED): DNSSEC + CA key hash

### How it works

Each domain CA publishes:

```text
_mqc-ca.foobar.com TXT "pubkey_hash=SHA256(...)"
```

Client flow:

1. Resolve TXT record **with DNSSEC validation**
2. Fetch CA pubkey from 8445
3. Verify:

```text
hash(fetched_key) == DNS value
```

If not → reject

---

### Why this works

* Attacker would need to:

  * break DNSSEC OR
  * control domain DNS

👉 That’s exactly the same trust model as modern web PKI (but simpler)

---

### What you must enforce

* DNSSEC validation REQUIRED (not optional)
* Reject unsigned DNS responses

---

## Option 2: DNS nonce + key binding (your idea, fixed)

Right now your nonce proves control, but not identity.

Fix it like this:

### Step 1

Client CA requests nonce from your server (8445)

### Step 2

They publish:

```text
_mqc-ca.foobar.com TXT:
nonce=abc123
pubkey_hash=XYZ
signature=Sign_CA(nonce || pubkey_hash)
```

### Step 3

Server verifies:

* DNS record exists
* Signature matches CA key
* Nonce matches issued value

---

### What this gives you

* Proof of domain control
* Proof of possession of CA key
* Binding between domain ↔ key

---

### Still requires:

👉 DNSSEC if you want real security

Otherwise DNS can be spoofed.

---

## Option 3: Multi-path TOFU (pragmatic upgrade)

If you want to keep TOFU but reduce risk:

When fetching CA key from 8445:

* Query from:

  * multiple IPs / networks
  * or via different resolvers

Accept only if:

```text
all sources return same key
```

---

### Why it helps

* Makes MITM harder (must control multiple paths)

### Why it’s not perfect

* Still bypassable by strong attacker

---

## Option 4: Transparency log (fits your Merkle tree nicely)

You already have a Merkle server.

Use it like Certificate Transparency:

* Every CA key registration is logged
* Clients can:

  * request inclusion proof
  * detect key changes

---

### Add policy:

```text
If CA key changes → require:
    - delay (e.g., 24h)
    - or multiple confirmations
```

---

# 🔒 How to tighten 8445 specifically

Here are concrete controls:

---

## 1. Strict input limits

* Max JSON size
* Max certificate size
* Max recursion depth

---

## 2. Rate limiting

Per:

* IP
* domain
* nonce requests

---

## 3. Nonce hardening

* 128+ bits randomness
* Expiration (short, e.g., 5–10 min)
* One-time use only

---

## 4. Require proof-of-work (optional)

For open systems:

```text
hash(nonce || solution) < target
```

Prevents spam CA/leaf creation.

---

## 5. Force key continuity

If a CA already exists:

```text
new_key must be signed by old_key
```

Prevents silent key takeover.

---

---

# 🔵 Now: tightening 8446 (MQC port)

This is your “secure channel”—you’re closer here already.

---

## Critical fixes (from earlier review)

### 1. ❗ Use length-prefixed frames (MANDATORY)

Right now:

* JSON framing is unsafe

Fix:

```c
uint32_t len = htonl(payload_len);
send(sock, &len, 4);
send(sock, payload, payload_len);
```

And read exactly that length.

---

### 2. Bind FULL transcript

Right now you hash fields.

Better:

```text
Transcript = exact bytes of all handshake frames
```

Then:

```text
Finished = HMAC(Transcript)
```

---

### 3. Sequence number handling

Fix:

* increment `recv_seq` ONLY after successful decrypt

---

### 4. Enforce mode early

Don’t do:

```c
MSG_PEEK + strstr("mode")
```

Instead:

* read framed ClientHello
* parse JSON
* route cleanly

---

### 5. Encrypted identity mode

Either:

* fully document it
* or remove it

Right now it’s ambiguous → dangerous.

---

### 6. Key binding (VERY IMPORTANT)

Ensure:

```text
hash(pubkey_from_disk) == subject_public_key_hash in cert
```

Without this:
👉 identity substitution attack

---

---

# 🧠 Clean architecture (what you’re building toward)

Here’s a strong version of your system:

---

## Bootstrap (8445)

* DNSSEC-verified CA key hash
* nonce-based domain validation
* Merkle log entry

---

## Secure channel (8446)

* PQ KEM handshake
* transcript-bound signatures
* AEAD encrypted channel

---

## Identity chain

```text
DNSSEC → CA key → Leaf cert → MQC session
```

---

# 🚀 If you want next step

I can:

* design the exact DNS TXT schema for your protocol
* give you drop-in C code for DNSSEC validation + key pinning
* or map MQC → TLS 1.3 equivalent security properties (so you know where you stand formally)

Right now you’re close—but the bootstrap trust step is the one thing that decides whether the whole system is secure or just “encrypted.”

### Issue 1 addressed

Numbered next steps:

1. **Exact DNS TXT schema for MQC**
2. Drop-in C code for DNSSEC validation + key pinning
3. MQC vs TLS 1.3 security-property map

## 1. Exact DNS TXT schema for MQC

Use a dedicated TXT name:

```text
_mqc-ca.<domain>
```

Example:

```text
_mqc-ca.foobar.com
```

Recommended TXT value:

```text
v=MQC1; role=ca; alg=ML-DSA-87; kh=sha3-256:<HEX_HASH>; nonce=<BASE64URL_NONCE>; exp=<UNIX_TIME>; sigalg=ML-DSA-87; sig=<BASE64URL_SIGNATURE>
```

Concrete example:

```text
_mqc-ca.foobar.com TXT "v=MQC1; role=ca; alg=ML-DSA-87; kh=sha3-256:9F2C...A81B; nonce=YzQ2kq7FJb-Ln9rR5xA2Ww; exp=1770000000; sigalg=ML-DSA-87; sig=MEUCIQD..."
```

The signed payload should be canonical and exact:

```text
MQC1|ca|foobar.com|ML-DSA-87|sha3-256:<HEX_HASH>|<NONCE>|<EXP>
```

Where:

```text
kh = SHA3-256(canonical_public_key_bytes)
```

The server verifies:

```text
DNS name == _mqc-ca.<claimed-domain>
v == MQC1
role == ca
nonce matches nonce issued by factsorlie.com:8445
exp has not expired
kh matches uploaded CA public key
sig verifies using uploaded CA public key over canonical payload
DNSSEC validates the TXT response
```

For leaf authorization, use a second record:

```text
_mqc-leaf.<leaf-id>._mqc.<domain>
```

Example:

```text
_mqc-leaf.alice._mqc.foobar.com TXT "v=MQC1; role=leaf; ca=foobar.com; leaf=alice; alg=ML-DSA-65; kh=sha3-256:ABCD...1234; nonce=<BASE64URL_NONCE>; exp=<UNIX_TIME>; sigalg=ML-DSA-87; sig=<CA_SIGNATURE>"
```

Leaf signed payload:

```text
MQC1|leaf|foobar.com|alice|ML-DSA-65|sha3-256:<LEAF_KEY_HASH>|<NONCE>|<EXP>
```

For leaves, the signature should be from the **domain CA**, not the leaf. That proves:

```text
foobar.com CA authorizes alice as a leaf
```

Minimum policy:

```text
CA TXT must be DNSSEC-valid.
Leaf registration must reference an already-registered CA.
Leaf nonce must be issued by the CA or by factsorlie.com on behalf of that CA.
CA key changes require old CA key signature unless emergency recovery mode is explicitly used.
```

This gives you:

```text
DNSSEC → domain control
CA signature → key possession
nonce → freshness
kh → domain/key binding
Merkle entry → public audit trail
```

### DNSSEC

Use **libunbound**. It performs DNSSEC validation in-process and exposes `result->secure` / `result->bogus`; if both are false, the domain is unsigned/insecure and should be rejected for MQC bootstrap. ([Unbound Documentation][1])

```bash
sudo apt install libunbound-dev
gcc -Wall -Wextra -O2 mqc_dnssec_pin.c -lunbound -lcrypto -o mqc_dnssec_pin
```

```c
/*
 * mqc_dnssec_pin.c
 *
 * DNSSEC TXT lookup + MQC CA key hash pinning.
 *
 * Requires:
 *   sudo apt install libunbound-dev libssl-dev
 *
 * Build:
 *   gcc -Wall -Wextra -O2 mqc_dnssec_pin.c -lunbound -lcrypto -o mqc_dnssec_pin
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#include <unbound.h>
#include <openssl/evp.h>

#define MQC_MAX_TXT_LEN 4096
#define MQC_HASH_HEX_LEN 64

typedef enum {
    MQC_DNSSEC_OK = 0,
    MQC_DNSSEC_NO_DATA,
    MQC_DNSSEC_BOGUS,
    MQC_DNSSEC_INSECURE,
    MQC_DNSSEC_RESOLVE_ERROR,
    MQC_DNSSEC_PARSE_ERROR,
    MQC_DNSSEC_HASH_MISMATCH
} mqc_dnssec_status_t;

static int hex_encode(const unsigned char *in, size_t in_len,
                      char *out, size_t out_len)
{
    static const char hexdigits[] = "0123456789abcdef";

    if (out_len < (in_len * 2 + 1))
        return -1;

    for (size_t i = 0; i < in_len; i++) {
        out[i * 2]     = hexdigits[(in[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hexdigits[in[i] & 0x0f];
    }

    out[in_len * 2] = '\0';
    return 0;
}

static int sha3_256_file_hex(const char *path, char out_hex[MQC_HASH_HEX_LEN + 1])
{
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fclose(fp);
        return -1;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(fp);
        return -1;
    }

    unsigned char buf[8192];
    size_t n;

    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (EVP_DigestUpdate(ctx, buf, n) != 1) {
            EVP_MD_CTX_free(ctx);
            fclose(fp);
            return -1;
        }
    }

    if (ferror(fp)) {
        EVP_MD_CTX_free(ctx);
        fclose(fp);
        return -1;
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(fp);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    fclose(fp);

    if (digest_len != 32)
        return -1;

    return hex_encode(digest, digest_len, out_hex, MQC_HASH_HEX_LEN + 1);
}

/*
 * DNS TXT RDATA format:
 *   one TXT RR can contain one or more length-prefixed character strings.
 *
 * This joins those strings into one C string.
 */
static int join_txt_rdata(const unsigned char *rdata, int len,
                          char *out, size_t out_len)
{
    size_t pos = 0;
    int i = 0;

    if (!rdata || len <= 0 || !out || out_len == 0)
        return -1;

    while (i < len) {
        unsigned int chunk_len = rdata[i++];

        if (i + (int)chunk_len > len)
            return -1;

        if (pos + chunk_len >= out_len)
            return -1;

        memcpy(out + pos, rdata + i, chunk_len);
        pos += chunk_len;
        i += chunk_len;
    }

    out[pos] = '\0';
    return 0;
}

static char *trim_left(char *s)
{
    while (*s && isspace((unsigned char)*s))
        s++;
    return s;
}

static void trim_right(char *s)
{
    size_t n = strlen(s);

    while (n > 0 && isspace((unsigned char)s[n - 1])) {
        s[n - 1] = '\0';
        n--;
    }
}

/*
 * Extract kh=sha3-256:<hex> from:
 *
 *   v=MQC1; role=ca; alg=ML-DSA-87;
 *   kh=sha3-256:<HEX>; nonce=...; exp=...; sigalg=...; sig=...
 */
static int extract_kh_sha3_256(const char *txt,
                               char out_hex[MQC_HASH_HEX_LEN + 1])
{
    char tmp[MQC_MAX_TXT_LEN];

    if (!txt || strlen(txt) >= sizeof(tmp))
        return -1;

    strncpy(tmp, txt, sizeof(tmp));
    tmp[sizeof(tmp) - 1] = '\0';

    char *saveptr = NULL;
    char *tok = strtok_r(tmp, ";", &saveptr);

    while (tok) {
        tok = trim_left(tok);
        trim_right(tok);

        const char *prefix = "kh=sha3-256:";
        size_t prefix_len = strlen(prefix);

        if (strncmp(tok, prefix, prefix_len) == 0) {
            const char *hex = tok + prefix_len;

            if (strlen(hex) != MQC_HASH_HEX_LEN)
                return -1;

            for (size_t i = 0; i < MQC_HASH_HEX_LEN; i++) {
                if (!isxdigit((unsigned char)hex[i]))
                    return -1;

                out_hex[i] = (char)tolower((unsigned char)hex[i]);
            }

            out_hex[MQC_HASH_HEX_LEN] = '\0';
            return 0;
        }

        tok = strtok_r(NULL, ";", &saveptr);
    }

    return -1;
}

/*
 * Fetch DNSSEC-validated TXT from _mqc-ca.<domain>.
 *
 * Important policy:
 *   result->secure must be true.
 *   result->bogus is fatal.
 *   secure=false && bogus=false means insecure/unsigned DNS, reject.
 */
static mqc_dnssec_status_t mqc_dnssec_fetch_ca_txt(const char *domain,
                                                   char *out_txt,
                                                   size_t out_txt_len)
{
    struct ub_ctx *ctx = NULL;
    struct ub_result *result = NULL;
    int rc;
    char qname[512];

    if (!domain || !out_txt || out_txt_len == 0)
        return MQC_DNSSEC_PARSE_ERROR;

    if (snprintf(qname, sizeof(qname), "_mqc-ca.%s", domain) >= (int)sizeof(qname))
        return MQC_DNSSEC_PARSE_ERROR;

    ctx = ub_ctx_create();
    if (!ctx)
        return MQC_DNSSEC_RESOLVE_ERROR;

    /*
     * Do NOT call ub_ctx_resolvconf(ctx, "/etc/resolv.conf") for MQC
     * bootstrap unless you intentionally trust your local resolver path.
     *
     * Without resolvconf, libunbound can act recursively itself.
     * NLnet Labs notes this is useful when you do not trust resolv.conf
     * servers or need DNSSEC validation.
     */

    rc = ub_ctx_add_ta_file(ctx, "/var/lib/unbound/root.key");
    if (rc != 0) {
        /*
         * Common alternatives:
         *   /usr/share/dns/root.key
         *   /etc/unbound/root.key
         */
        ub_ctx_delete(ctx);
        return MQC_DNSSEC_RESOLVE_ERROR;
    }

    rc = ub_resolve(ctx, qname, 16 /* TXT */, 1 /* IN */, &result);
    if (rc != 0 || !result) {
        ub_ctx_delete(ctx);
        return MQC_DNSSEC_RESOLVE_ERROR;
    }

    if (result->bogus) {
        ub_resolve_free(result);
        ub_ctx_delete(ctx);
        return MQC_DNSSEC_BOGUS;
    }

    if (!result->secure) {
        ub_resolve_free(result);
        ub_ctx_delete(ctx);
        return MQC_DNSSEC_INSECURE;
    }

    if (!result->havedata || !result->data || !result->data[0]) {
        ub_resolve_free(result);
        ub_ctx_delete(ctx);
        return MQC_DNSSEC_NO_DATA;
    }

    if (join_txt_rdata((const unsigned char *)result->data[0],
                       result->len[0],
                       out_txt,
                       out_txt_len) != 0) {
        ub_resolve_free(result);
        ub_ctx_delete(ctx);
        return MQC_DNSSEC_PARSE_ERROR;
    }

    ub_resolve_free(result);
    ub_ctx_delete(ctx);

    return MQC_DNSSEC_OK;
}

/*
 * Main drop-in function:
 *
 *   domain:            "foobar.com"
 *   ca_pubkey_path:    path to fetched/staged CA public key
 *
 * Returns MQC_DNSSEC_OK only if:
 *   - DNSSEC validation succeeds
 *   - TXT record exists
 *   - kh=sha3-256:<hash> is present
 *   - hash(public-key-file) matches DNS TXT hash
 */
mqc_dnssec_status_t mqc_pin_ca_key_from_dnssec(const char *domain,
                                               const char *ca_pubkey_path)
{
    char txt[MQC_MAX_TXT_LEN];
    char dns_hash[MQC_HASH_HEX_LEN + 1];
    char file_hash[MQC_HASH_HEX_LEN + 1];

    mqc_dnssec_status_t st =
        mqc_dnssec_fetch_ca_txt(domain, txt, sizeof(txt));

    if (st != MQC_DNSSEC_OK)
        return st;

    if (extract_kh_sha3_256(txt, dns_hash) != 0)
        return MQC_DNSSEC_PARSE_ERROR;

    if (sha3_256_file_hex(ca_pubkey_path, file_hash) != 0)
        return MQC_DNSSEC_PARSE_ERROR;

    if (strcmp(dns_hash, file_hash) != 0)
        return MQC_DNSSEC_HASH_MISMATCH;

    return MQC_DNSSEC_OK;
}

const char *mqc_dnssec_status_string(mqc_dnssec_status_t st)
{
    switch (st) {
    case MQC_DNSSEC_OK:
        return "OK";
    case MQC_DNSSEC_NO_DATA:
        return "No TXT data";
    case MQC_DNSSEC_BOGUS:
        return "DNSSEC bogus/tampered";
    case MQC_DNSSEC_INSECURE:
        return "DNSSEC insecure or unsigned";
    case MQC_DNSSEC_RESOLVE_ERROR:
        return "DNS resolution error";
    case MQC_DNSSEC_PARSE_ERROR:
        return "Parse/hash error";
    case MQC_DNSSEC_HASH_MISMATCH:
        return "CA public key hash mismatch";
    default:
        return "Unknown error";
    }
}

#ifdef MQC_DNSSEC_PIN_TEST
int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <domain> <ca_pubkey_file>\n", argv[0]);
        return 2;
    }

    mqc_dnssec_status_t st =
        mqc_pin_ca_key_from_dnssec(argv[1], argv[2]);

    printf("%s\n", mqc_dnssec_status_string(st));

    return st == MQC_DNSSEC_OK ? 0 : 1;
}
#endif
```

Compile test mode:

```bash
gcc -Wall -Wextra -O2 -DMQC_DNSSEC_PIN_TEST \
    mqc_dnssec_pin.c -lunbound -lcrypto -o mqc_dnssec_pin
```

Example policy for your **8445 bootstrap**:

```c
st = mqc_pin_ca_key_from_dnssec("foobar.com", "/tmp/foobar-ca.pub");

if (st != MQC_DNSSEC_OK) {
    reject_registration();
}
```

Important rule: for MQC, treat `secure == false && bogus == false` as failure. Libunbound describes that state as “no security information for that domain,” meaning unsigned/insecure DNS, not validated DNSSEC. ([NLnet Labs][2])

[1]: https://unbound.docs.nlnetlabs.nl/en/latest/manpages/libunbound.html?utm_source=chatgpt.com "libunbound(3) — Unbound 1.24.2 documentation"
[2]: https://www.nlnetlabs.nl/documentation/unbound/libunbound/?utm_source=chatgpt.com "NLnet Labs Documentation - Unbound - libunbound.3"

### Compare with TLS


