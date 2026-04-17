# FIPS Framework — Source Integrity Tools

Self-contained tools for registering and verifying FIPS source kits against
the MTC transparency log server. No OpenSSL dependency — uses wolfCrypt
natively for SHA-256 hashing and Ed25519 signature verification.

## Tools

| Tool | Purpose | When to use |
|------|---------|-------------|
| `fips-manifest-submit` | Hash source files, submit manifest to MTC server, save receipt | After building a kit (developer/CI) |
| `fips-manifest-verify` | Replay Merkle proof, verify Ed25519 cosignature, check file hashes | Before using a kit (developer/user) |

## Building

```bash
cd fips-framework
make
```

Requires wolfCrypt headers and library (built from the parent postWolf tree).

## Usage

### Registering a kit (publisher)

```bash
# Set the MTC server URL
export MTC_SERVER=factsorlie.com:8080

# After building postWolf with FIPS:
./fips-manifest-submit --package postWolf \
                       --tag v5.9.0 \
                       --source-dir ../wolfcrypt/src \
                       --output fips-manifest-receipt.json
```

The tool:
1. Computes SHA-256 of every FIPS source file
2. Builds a canonical JSON manifest (sorted by path, includes `expires`)
3. POSTs the manifest to `$MTC_SERVER/fips/manifest`
4. Saves the server's receipt (manifest + inclusion proof + cosignature)

Ship `fips-manifest-receipt.json` with the release tarball.

### Verifying a kit (user)

**Online (recommended):**
```bash
export MTC_SERVER=factsorlie.com:8080

./fips-manifest-verify --receipt fips-manifest-receipt.json \
                       --source-dir ../wolfcrypt/src
```

**Offline:**
```bash
./fips-manifest-verify --receipt fips-manifest-receipt.json \
                       --source-dir ../wolfcrypt/src \
                       --offline \
                       --ca-key config/ca-pubkey.bin
```

The tool:
1. Checks manifest expiration (`expires` field)
2. Checks for version rollback against local state
3. Computes SHA-256 of every local source file
4. Compares against the manifest in the receipt
5. Replays the Merkle inclusion proof (hash chain from leaf to root)
6. Verifies the Ed25519 cosignature with the CA public key

## Configuration

### CA Public Key

The pinned CA public key (32 bytes, Ed25519) is needed for offline
verification. Obtain it out-of-band:

- DNS TXT: `dig TXT _mtc-ca-key.factsorlie.com +short`
- MTC server: connect to `factsorlie.com` and query `GET /ca/public-key`
- Project website or signed git tag

Store it in `config/ca-pubkey.bin` or set `MTC_CA_PUBKEY` env var.

### Rollback State

The verify tool tracks the highest accepted version per package in
`~/.config/mtc-fips/last-verified.json`. Use `--allow-rollback` to
override for legitimate downgrades.

## Files

```
fips-framework/
    README.md                     This file
    Makefile                      Builds both tools against wolfCrypt
    fips-manifest-submit.c        Kit registration tool
    fips-manifest-verify.c        Kit verification tool
    config/
        ca-pubkey.h               Pinned CA public key (compiled in)
```

## How It Works

```
Publisher                           MTC Server
=========                           ==========

source files                        Merkle Tree (append-only)
    |                                    |
    +-- SHA-256 each file               |
    +-- Build manifest JSON             |
    +-- POST /fips/manifest --------->  +-- Append as leaf
    |                                    +-- Compute inclusion proof
    +-- Save receipt <----------------  +-- Sign root (Ed25519)


Verifier                            
========                            

source files + receipt              
    |                               
    +-- SHA-256 each file           
    +-- Compare to manifest         
    +-- Replay inclusion proof      
    +-- Verify Ed25519 cosignature  
    +-- PASS or FAIL                
```

No OpenSSL. No cert chain files. One receipt file. One pinned CA key.
