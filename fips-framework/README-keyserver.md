# GPG Keyserver Status

## Key

- **Owner:** Cal Page <page.cal@gmail.com>
- **Fingerprint:** `E9C0 59EC 0D32 64FA B35F 94AD 465B F9F6 F8EB 475A`

## Keyservers

| Keyserver | URL | Status (2026-04-05) |
|-----------|-----|---------------------|
| OpenPGP | keys.openpgp.org | Not found |
| Ubuntu | keyserver.ubuntu.com | Not found |
| MIT | pgp.mit.edu | Only an expired test key (`page.cal.test@gmail.com`, RSA 4096, expired 2021-11-13) |

## Publishing

The key is not currently published. To upload:

```bash
gpg --keyserver keys.openpgp.org --send-keys E9C059EC0D3264FAB35F94AD465BF9F6F8EB475A
```

This is recommended if the GPG key will be used as an out-of-band trust
anchor for the FIPS framework (e.g., signing git tags that pin the CA
public key).
