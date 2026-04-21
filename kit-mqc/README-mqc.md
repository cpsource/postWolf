# postWolf mqc kit

A single-tool kit that carries just the `mqc` symmetric-crypto CLI
and its `libpostWolf.so` runtime dependency — nothing else from
the postWolf tree.

## What's inside

```
payload/
  bin/mqc                          the CLI
  lib/libpostWolf.so*              wolfSSL-derived crypto (AES-256-GCM, scrypt)
  doc/README.md                    this file
  doc/README-mqc-cli.md            full mqc reference
  install-mqc-kit.sh               one-shot installer (sudo bash)
  VERSION                          git describe at build time
```

## Install on the target box

```bash
tar xzf postWolf-mqc-kit-<version>.tar.gz
cd payload
sudo bash install-mqc-kit.sh
```

The installer:
1. `apt install libjson-c5` (runtime JSON parser).
2. Copies `libpostWolf.so*` into `/usr/local/lib/`, runs `ldconfig`.
3. Copies `mqc` into `/usr/local/bin/`.
4. Copies docs into `/usr/local/share/doc/postWolf-mqc/`.
5. Sanity-checks `ldd /usr/local/bin/mqc` for unresolved libraries.

## Target compatibility

- Built against Ubuntu 24.04 (`libc6`, `libjson-c5`).
- Works on any x86_64 Ubuntu/Debian where `libjson-c5` is
  installable via apt and glibc is compatible with the build host's
  (24.04 → 24.04 is the safe pair).
- For WSL2 users on Windows 11: install inside your Ubuntu 24.04
  WSL distro, then invoke from Windows PowerShell / cmd via
  `wsl mqc --help`.

## First-run setup

`mqc` needs either:
- a **master password** in `~/.env` (used with `--env`), or
- a **per-domain password cache** under `~/.TPM/<domain>/mqc-password.pw`
  (populated via `--password <PW>` on first use).

Fastest path:

```bash
# pick a strong 16-char password
mqc --encode --complex-password </dev/null >/dev/null
# → "Generated password: <16 chars>" on stderr

# put it in ~/.env
echo 'MQC_MASTER_PASSWORD="<16 chars>"' > ~/.env
chmod 600 ~/.env

# round-trip check
echo hello | mqc --encode --env --no-cache | mqc --decode --env --no-cache
# → hello
```

Full flag reference and every supported flow (streaming, `--file`
autodetect, `--out`, `--complex-password`, `--dry-run`, etc.) is in
`/usr/local/share/doc/postWolf-mqc/README-mqc-cli.md`.

## Uninstall

```bash
sudo rm /usr/local/bin/mqc
sudo rm /usr/local/lib/libpostWolf.so*
sudo rm -r /usr/local/share/doc/postWolf-mqc
sudo ldconfig
```

Your own `~/.env` and `~/.TPM/` are not touched by uninstall —
remove them separately if you're retiring the host entirely.
