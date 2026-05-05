# postWolf developer setup

Single-script bootstrap for a fresh box that wants to **clone postWolf
and build it from source**.

```bash
sudo bash prerequisites.sh
git clone https://github.com/cpsource/postWolf.git
cd postWolf
./make-all.sh
```

That's the whole flow.

## What `prerequisites.sh` installs

| Group | Packages |
|-------|----------|
| Build | `build-essential pkg-config autoconf automake libtool` |
| Source-fetch | `git wget perl zlib1g-dev libssl-dev` (also covers `kit-CA/buildopenssl4.0.sh`) |
| postWolf `-dev` deps | `libjson-c-dev libpq-dev libcurl4-openssl-dev libhiredis-dev libunbound-dev` |
| Runtime services (for local testing) | `postgresql-client redis-server` |
| DNSSEC validation runtime | `dnsutils dns-root-data` |
| Python tooling | `python3 python3-pip python3-cryptography` plus `pip3 install psycopg2-binary` |

The script is idempotent — re-run it whenever you suspect a missing
dep, it'll just no-op on the satisfied ones.

## What this kit is *not*

This isn't a packaged install kit like `kit-CA/`, `kit-leaf/`, or
`kit-server/` (which ship pre-built binaries inside a tarball).  It
just gets a developer machine ready to compile postWolf themselves.
For end-user installs, use one of the other three kits.

## OpenSSL 4.0.0

`prerequisites.sh` does **not** build OpenSSL 4.0.0.  Most postWolf
build paths don't need it; only the ML-DSA-87 keygen helpers
(`create_ca_cert.py`, `create_leaf_keypair.py`,
`create_server_cert.py`) shell out to `openssl40`.  If you need it:

```bash
sudo bash kit-CA/buildopenssl4.0.sh
```

(~5–10 minute first-time build; idempotent thereafter.)
