# postWolf CA-operator kit

Everything a CA operator needs to enrol a CA against a postWolf MTC
server, issue leaf-enrollment nonces, revoke leaves, and inspect the
log. Superset of the leaf kit — all leaf-user tools are included too.

This kit does **not** include `mtc_server` itself; if you want to run
your own MTC CA/log server, that's a separate kit. As a CA *operator*
you can be a client of someone else's MTC server (e.g. factsorlie.com)
or of your own.

## What's in the kit

| Path | Purpose |
|------|---------|
| `bin/bootstrap_ca`      | First-time CA enrollment — DH bootstrap on port 8445, DNS TXT validates domain ownership. |
| `bin/issue_leaf_nonce`  | Issue a 15-min nonce authorising a specific (domain, leaf pubkey) pair. CA-authenticated, MQC. |
| `bin/revoke-key`        | Revoke a leaf in your CA's domain with a CA-signed payload; also `--list` / `--refresh` for everyone. |
| `bin/admin_recosign`    | Operational tool to re-cosign subtrees (maintenance). |
| `bin/bootstrap_leaf`    | Leaf enrollment (included for completeness — run it if this host also has leaf identities). |
| `bin/show-tpm`          | Inspect local identities (CA or leaf); `--verify` walks the full trust chain against the log. |
| `bin/create_ca_cert.py` | Generate the CA's ML-DSA-87 keypair + self-signed X.509 cert (uses `openssl35`). |
| `bin/create_leaf_keypair.py` | Generate an ML-DSA-87 (or EC-P256 / Ed25519) keypair for a leaf under your domain. |
| `bin/ca_dns_txt.py`     | Compute the DNS TXT record value that proves domain ownership during `bootstrap_ca`. |
| `lib/libpostWolf.so*`   | wolfSSL-derived shared library. |
| `socket-level-wrapper-MQC.tar.gz` | Source + prebuilt `libmqc.a` for the MQC wrapper. |
| `mqc.pc`                | pkg-config descriptor for downstream C code that links `libmqc`. |
| `buildopenssl3.5.sh`    | Builds OpenSSL 3.5 into `/usr/local/ssl/` and drops `/usr/local/bin/openssl35`. |
| `install-ca-kit.sh`     | Installs everything to `/usr/local/` — must be run with sudo. |
| `VERSION`               | Git describe of the source tree. |

## Install

```bash
tar xzf postWolf-ca-kit-<version>.tar.gz
cd payload
sudo bash install-ca-kit.sh
```

The installer:

1. apt-installs runtime libs (`libjson-c5`, `libcurl4`, `libpq5`,
   a `libhiredis` variant).
2. **Builds OpenSSL 3.5 from source** the first time through (5–10 min)
   and exposes it as `/usr/local/bin/openssl35`. Re-runs are no-ops.
3. Installs `libpostWolf.so*` → `/usr/local/lib/` + `ldconfig`.
4. Installs MQC headers → `/usr/local/include/mqc/`, `libmqc.a` →
   `/usr/local/lib/`, `mqc.pc` → `/usr/local/lib/pkgconfig/`.
5. Installs all six CA tools → `/usr/local/bin/`.
6. Runs `ldd` on each tool and warns about any unresolved `.so`.

## First-time CA enrollment

A CA binds a post-quantum keypair to a domain. Domain ownership is
proved with a DNS TXT record; no nonce is needed.

```bash
# 1. Generate ML-DSA-87 keypair + self-signed CA cert
create_ca_cert.py --domain <DOMAIN>
# → ~/.mtc-ca-data/<DOMAIN>/{private_key,public_key,ca_cert}.pem

# 2. Compute the DNS TXT record and publish it at _mtc-ca.<domain>
ca_dns_txt.py ~/.mtc-ca-data/<DOMAIN>/ca_cert.pem
# → prints the exact record the domain owner should add

# 3. Run the bootstrap once DNS has propagated
bootstrap_ca --domain <DOMAIN> \
             --server <MTC-SERVER>:8445 \
             --key-file ~/.mtc-ca-data/<DOMAIN>/private_key.pem
```

bootstrap_ca does an X25519 DH exchange with the server, submits your
CSR, waits for the server to resolve the DNS TXT, and on success
receives your issued CA certificate. Everything lands in
`~/.TPM/<DOMAIN>-ca/` (note the `-ca` suffix):

```
~/.TPM/<DOMAIN>-ca/
    private_key.pem    # ML-DSA-87 private key, mode 0600
    public_key.pem
    certificate.json   # MTC cert + Merkle proof + cosignature
    index              # CA's log index (used by revoke-key)
```

## Issue a leaf nonce

Once enrolled, you authorise specific leaves by issuing them a nonce.
This is the CA's "this leaf is allowed to enrol under my domain"
statement, bound to a specific public-key fingerprint and a 15-minute
TTL.

```bash
issue_leaf_nonce --domain <DOMAIN> --key-file leaf-pub.pem
# → prints:
#     Leaf enrollment nonce issued:
#       Domain:    <DOMAIN>
#       Nonce:     <64 hex chars>
#       Expires:   <epoch> (15 minutes)
#       CA index:  N
```

Send the nonce to the leaf user out of band. They run `bootstrap_leaf`
with it to complete enrollment. Re-running `issue_leaf_nonce` with the
same `(domain, key-file)` within the 15-min window returns the same
nonce (idempotent).

## Revoke a leaf

```bash
revoke-key --target-index N --reason "key compromise"
```

`revoke-key` auto-detects your CA identity (`*-ca` directory under
`~/.TPM/`), signs the revocation with the CA's private key, and POSTs
it over MQC. The server enforces:

- caller is a CA (subject ends in `-ca`),
- target is a leaf (subject does not end in `-ca`),
- target subject is `<ca-domain>` or `*.<ca-domain>`,
- caller is not revoking itself,
- ±5 minute timestamp freshness,
- signature verifies against the CA's logged public key.

`revoke-key --list <DOMAIN>` lists revoked leaves in a domain (anyone
can run — it's a public read). `revoke-key --refresh` updates every
cached `~/.TPM/peers/<n>/revoked.json` from the server's current
`/revoked` list, bypassing the 24 h TTL.

## Day-to-day operations

```bash
show-tpm --verify                     # full chain: cert + Merkle proof + cosig
admin_recosign <subtree-start> <end>  # operational: re-cosign a subtree
```

## Uninstall

```bash
sudo rm -f /usr/local/bin/{bootstrap_ca,bootstrap_leaf,show-tpm,issue_leaf_nonce,admin_recosign,revoke-key,create_ca_cert.py,create_leaf_keypair.py,ca_dns_txt.py}
sudo rm -f /usr/local/lib/libpostWolf.so*
sudo rm -f /usr/local/lib/libmqc.a
sudo rm -f /usr/local/lib/pkgconfig/mqc.pc
sudo rm -rf /usr/local/include/mqc
sudo rm -rf /usr/local/share/doc/postWolf-ca
sudo ldconfig

# Optional: wipe openssl35 too
sudo rm -rf /usr/local/ssl /usr/local/bin/openssl35 /usr/local/src/openssl-3.5.0

# Optional: rm -rf ~/.TPM/   (deletes your CA and leaf identities!)
```

## More

- Top-level project overview: [postWolf README](https://github.com/cpsource/postWolf).
- Server-side endpoint reference:
  `mtc-keymaster/server2/c/README-using-mtc-server.md` (especially
  `POST /revoke` and the enrollment flows).
- Open issues / roadmap: `mtc-keymaster/README-bugsandtodo.md`.
