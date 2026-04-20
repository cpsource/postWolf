Short answer: there is no official “AES-next” with more than 256-bit keys.

What AES actually is
The standard we call Advanced Encryption Standard (defined in FIPS 197) has exactly three key sizes:

128 bits
192 bits
256 bits (the largest)
There is no AES-512 or AES-1024 in the standard.

Why doesn’t AES go beyond 256 bits?
A few reasons, and they’re practical—not theoretical limits:

256-bit keys are already beyond brute-force reach
Even with hypothetical future computing, 2^{256} possibilities is astronomically large.
Security bottlenecks shift elsewhere
Attacks on AES don’t scale simply with key size. The structure (rounds, S-boxes, etc.) matters more than just “more bits.”
Performance cost vs benefit
Larger keys would slow things down with almost no real-world gain.
So what
is “next” after AES-256?
Instead of “bigger AES,” the field moved in different directions:

1. Post-quantum cryptography
Quantum computers (if large enough) would weaken some systems, so newer algorithms are being standardized by National Institute of Standards and Technology, such as:

CRYSTALS-Kyber (key exchange)
CRYSTALS-Dilithium (signatures)
These don’t replace AES directly—they complement it.

2. Stronger modes / constructions
Rather than increasing key size, we improve how AES is used:

AES-GCM (authenticated encryption)
AES-XTS (disk encryption)
AES-SIV (misuse-resistant)
3. “Wider” constructions (if you really want more bits)
There are theoretical approaches like:

AES-512 via cascading (e.g., encrypt twice with different keys)
Wide-block ciphers (e.g., Threefish, used in Skein)
But these are not standardized replacements for AES.

Bottom line
AES-256 is the top of the official AES line
There is no “AES-512” successor
Future cryptography is focusing on quantum resistance and better designs, not just bigger keys
If you want, I can show you what an “AES-512” design would look like (and why it’s not commonly used)—it actually ties into your work on post-quantum TLS and multi-key certificates.


If you want to encrypt a stream of data in a post-quantum safe way, the answer is a bit counterintuitive:

👉 You still use AES (or ChaCha20) for the stream itself.
👉 The post-quantum part is used for key exchange, not bulk encryption.

🔑 The standard modern design (PQ-safe stream encryption)
1) Post-quantum key exchange
Use a PQ KEM (Key Encapsulation Mechanism), e.g.:

CRYSTALS-Kyber (now standardized as ML-KEM)
This securely establishes a shared secret—even against quantum attackers.

2) Derive a symmetric session key
From that shared secret, derive a key using a KDF (HKDF, etc.)

3) Encrypt the stream with a fast symmetric cipher
Now use a classical stream or AEAD cipher:

AES-GCM
ChaCha20-Poly1305
These are already considered quantum-resistant enough for symmetric encryption.

🤔 Why not a “post-quantum stream cipher”?
Because:

Grover’s algorithm (quantum attack) only gives a quadratic speedup
→ AES-256 effectively becomes ~128-bit security (still very strong)
There’s no practical advantage to replacing AES/ChaCha20 with something exotic
PQ research has focused on:
Key exchange (Kyber)
Signatures (Dilithium)
—not stream ciphers

🧠 Mental model
Think of it like this:

[ PQ Key Exchange ]  →  [ Shared Secret ]  →  [ AES-256 Stream Encryption ]
       (Kyber)                                  (fast, proven)
⚠️ What
not to do
❌ Don’t try to “invent” a PQ stream cipher unless you’re doing research
❌ Don’t just increase key size arbitrarily (e.g., AES-512 hacks)
❌ Don’t reuse nonces in AES-GCM / ChaCha20 (critical)
🛠️ Real-world example
Modern TLS 1.3 (post-quantum hybrid) does exactly this:

Key exchange: Kyber + classical (ECDHE)
Bulk encryption: AES-GCM or ChaCha20
🧩 If you want something more experimental
There are research directions like:

Sponge-based ciphers (e.g., based on Keccak / SHA-3)
Wide-pipe constructions (your kind of thinking 👀)
Lattice-based symmetric designs (rare, mostly academic)
But none have displaced AES/ChaCha20.

✅ Bottom line
For a PQ-secure stream:

Key exchange: Kyber
Stream encryption: AES-256-GCM or ChaCha20-Poly1305
That’s the current best practice—even in cutting-edge systems.

If you want, I can sketch a C or Python implementation of a Kyber + AES-GCM streaming pipeline (fits nicely with your TLS / MTC ideas).

3
Inbox

Cal Page <page.cal@gmail.com>
Sun, Apr 19, 9:35 PM (5 hours ago)
to me

Here’s a clean, accurate walkthrough of TLS 1.3 key exchange, without the legacy clutter.

🔐 TLS 1.3 Key Exchange (step-by-step)
TLS 1.3 uses ephemeral Diffie–Hellman to agree on a shared secret, then derives all keys from that.

1) ClientHello (client → server)
The client sends:

Supported cipher suites (e.g. AES-GCM)
Supported groups (elliptic curves like X25519)
A key share (public key)
Example:

ClientHello:
  key_share: X25519 public key (client_ephemeral_pub)
👉 This is already a big change from TLS 1.2:
the client sends its DH key immediately (1-RTT handshake)

2) ServerHello (server → client)
The server responds with:

Chosen cipher suite
Chosen group
Its own ephemeral public key
ServerHello:
  key_share: X25519 public key (server_ephemeral_pub)
3) Shared secret is computed (both sides)
Now both sides compute the same value:

\text{shared\_secret} = (g^{ab}) \mod p

More concretely:

Client computes: client_priv * server_pub
Server computes: server_priv * client_pub
👉 Same result on both sides.

4) Key Schedule (HKDF)
TLS 1.3 doesn’t use the raw shared secret directly.
It feeds it into a structured key schedule using HKDF.

Core idea:
\text{Handshake Secret} = \text{HKDF-Extract}(shared\_secret)

Then derives:

Handshake traffic keys (encrypt handshake)
Application traffic keys (encrypt data)
5) Server proves identity (authentication)
After ServerHello:

Server sends its certificate
Server signs handshake transcript with its private key
This proves:
👉 “I am the real server AND I participated in this key exchange”

6) Encrypted handshake finishes
Both sides send Finished messages
These are MACs over the handshake transcript
At this point:
✅ Key exchange is complete
✅ Encryption is active
✅ Both sides are authenticated (server always, client optionally)

🧠 Visual flow
Client                          Server
------                          ------

ClientHello (pub_C)  ───────▶

                         ServerHello (pub_S)
                         Certificate
                         Signature
                ◀───────

[ compute shared secret ]

Finished            ───────▶
                    ◀─────── Finished

==== Secure channel established ====
⚡ What’s special about TLS 1.3
1. Forward secrecy by default
Uses ephemeral keys only
If server key is stolen later → past sessions still safe
2. No RSA key exchange anymore
Older TLS:

RSA encrypted premaster secret ❌
TLS 1.3:

Only (EC)DHE ✔
3. Faster (1 round trip)
Handshake completes in 1 RTT

🔐 Where post-quantum fits
Standard TLS 1.3 uses:

X25519 or P-256 (not quantum safe)
Post-quantum hybrid replaces step (3):

Instead of:

shared_secret = ECDHE
You do:

shared_secret = combine(ECDHE, Kyber)
Using:

CRYSTALS-Kyber
🧩 Final takeaway
TLS 1.3 key exchange is:

Exchange ephemeral public keys
Compute shared secret (Diffie–Hellman)
Derive keys with HKDF
Authenticate with signatures
Start encrypted communication
If you want, I can map this directly onto your custom TLS / MTC / Merkle design—you’re already thinking along the same lines (nonce, proofs, etc.).

🔑 What HKDF is (in plain terms)
HKDF is a standard way to turn some shared secret (like a Diffie–Hellman result) into strong, structured cryptographic keys.

Think of it as:

“Take raw entropy → clean it → stretch it → label it → produce many safe keys”

It’s defined in RFC 5869 and used heavily in TLS 1.3.

🧠 Why HKDF exists
The raw shared secret you get from key exchange:

might not be uniformly random
might be biased or structured
should not be used directly as an encryption key
👉 HKDF fixes that.

⚙️ Two-stage design
HKDF has two phases:

1) Extract (normalize entropy)
This step turns your input into a clean, fixed-length secret.

PRK = HMAC_{salt}(IKM)

IKM = Input Keying Material (e.g., DH shared secret)
salt = optional randomness (often previous secret in TLS)
PRK = pseudorandom key (cleaned output)
👉 This is like “distilling” your entropy.

2) Expand (generate keys)
Now you generate as many keys as you want:

OKM = HMAC_{PRK}(T_{n-1} \parallel info \parallel n)

info = context label (VERY important)
n = counter (1, 2, 3…)
OKM = output key material
👉 This is like “minting labeled keys from a master secret.”

🧩 Key idea: context separation
The info field prevents key reuse problems.

Example:

"tls13 handshake key"
"tls13 application key"
"tls13 finished key"
Same input → different outputs because labels differ.

🔐 How TLS 1.3 uses HKDF
TLS 1.3 builds a chain of secrets:

early_secret
      ↓
handshake_secret
      ↓
master_secret
Each step is:

HKDF-Extract with new input
HKDF-Expand with labels
So you get:

client handshake key
server handshake key
client app key
server app key
👉 All derived safely from one shared secret.

⚡ Why this design is powerful
1. Safe even with imperfect input
Even if your shared secret isn’t perfect, Extract fixes it

2. Unlimited key generation
You can derive:

encryption keys
MAC keys
IVs
subkeys
All from one root

3. Cryptographic isolation
Keys are independent because of info labels

4. Forward secrecy chaining
You can “mix in” new secrets over time:

rekeying
session updates
🧠 Mental model
[ shared secret ]
        ↓  (Extract)
   [ master key ]
        ↓  (Expand with labels)
 ┌───────────────┬───────────────┬───────────────┐
 handshake_key   app_key         finished_key
⚠️ Subtle but important details
Never skip Extract unless you know your input is high-quality
Always use meaningful info labels
Never reuse keys across contexts
HKDF is built on HMAC (usually SHA-256)
🧩 Relating this to your work
Given your interest in:

TLS redesign
Merkle / certificate systems
PQ key exchange
HKDF is the glue layer:

👉 It lets you combine multiple secrets safely:

shared_secret = HKDF-Extract(
    salt,
    ECDHE || Kyber || nonce || transcript_hash
)
That’s exactly how hybrid PQ-TLS works conceptually.

✅ Bottom line
HKDF is:

a secure entropy normalizer (Extract)
a key generator with context (Expand)
the core of TLS 1.3 key derivation
If you want, I can walk through a byte-level example (actual HMAC inputs/outputs) or show how to implement HKDF in C with OpenSSL/libsodium.


---

## Appendix: Does MQC use CRYSTALS-Kyber / ML-KEM?

**Yes.** MQC uses **ML-KEM-768** (CRYSTALS-Kyber at the category-3
parameter set) as its key-exchange primitive.

Evidence, all in `socket-level-wrapper-MQC/mqc.c`:

| Line | Call | Role |
|---|---|---|
| 701 | `wc_MlKemKey_Init(&mlkem, WC_ML_KEM_768, ...)` | pick the 768 parameter set |
| 705 | `wc_MlKemKey_MakeKey(&mlkem, &rng)` | server's ephemeral keypair |
| 713 | `wc_MlKemKey_EncodePublicKey(&mlkem, ...)` | server serializes pk for the wire |
| 997 | `wc_MlKemKey_DecodePublicKey(&mlkem, ...)` | client parses the pk |
| 1005 | `wc_MlKemKey_Encapsulate(&mlkem, ct, ss, &rng)` | client picks shared secret, wraps as ct |
| 829 | `wc_MlKemKey_Decapsulate(&mlkem, ss, ct, ct_sz)` | server unwraps to get ss |

And from the file's own module header (`mqc.c` lines 7-13):

> *"ML-KEM-768 key exchange, ML-DSA-87 signed authentication, and
> AES-256-GCM… Both derive AES-256-GCM key from ML-KEM shared secret."*

So every live MQC handshake on `factsorlie.com:8446` runs ML-KEM-768
— the shared secret goes through HKDF-SHA256 to produce the 32-byte
AES-256-GCM session key. The DH bootstrap port (8445) is the only
place postWolf still uses classical X25519.

See `README-ml-kem.md` at the repo root for a deeper treatment:
Kyber → ML-KEM nomenclature, KEM vs classical DH asymmetry, size
table vs X25519, the three NIST parameter sets, Module-LWE +
Fujisaki-Okamoto math sketch, and the condensed handshake snippet.


