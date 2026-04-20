# postWolf mqc — Gmail extension (Chrome/Edge on Windows + WSL2)

A small two-layer bridge that lets you right-click selected text in
Gmail and encode/decode it with the postWolf `mqc` CLI that runs
inside WSL2.  No server, no third-party service — it's a shell-out
from the browser to your own machine.

```
 +--------------------+       +----------------+       +------------+
 |   Chrome / Edge    |  NM   | Native host    |  pipe |   WSL2     |
 |  (MV3 extension)   |<----->| (Python shim)  |<----->|  /usr/     |
 |  content-script +  | stdio |  Windows side  | stdin |  local/bin/|
 |   service worker   |       |                | stdout|    mqc     |
 +--------------------+       +----------------+       +------------+
        extension/                 host/               (kit-mqc install)
```

## Layout

- **`host/`** — the Chrome **Native Messaging** shim.
  Windows-side Python script + a `.cmd` launcher + an `install.ps1`
  that writes the HKCU registry entry pointing Chrome at it.  See
  `host/README.md`.
- **`extension/`** — the **Chrome MV3 extension** loaded
  unpacked.  Owns the two context-menu items (Encode / Decode) and
  the overlay for showing decode results.  See
  `extension/README.md`.

## Start-to-finish install

Assumes:
- Windows 11 with WSL2 Ubuntu 24.04 installed (`wsl --install`).
- The postWolf mqc kit already installed inside WSL
  (`sudo bash kit-mqc/install-mqc-kit.sh`) and
  `~/.env` populated with `MQC_MASTER_PASSWORD="..."`.
- Python 3 on the Windows PATH
  (`winget install Python.Python.3` or Microsoft Store).

Steps:

1. **Load the extension.**
   Chrome → `chrome://extensions` → turn on *Developer mode* →
   *Load unpacked* → select `gmail-mqc-extension/extension/`.
   Note the 32-char extension ID Chrome assigns.

2. **Register the shim.**
   From a Windows PowerShell:
   ```powershell
   cd gmail-mqc-extension\host
   .\install.ps1 -ExtensionId <the-id-from-step-1>
   ```

3. **Reload the extension** in `chrome://extensions` so Chrome
   re-reads the native-host allowlist.

4. **Sanity-check** — click the extension's toolbar icon →
   *Ping native host*.  You should see the first lines of
   `mqc --help` inside the status box.

5. **Use it.**
   Open Gmail.  Right-click any selected text:
   - *Encode with mqc* — in a compose window, replaces the selection
     with a one-line `mqc-1` JSON envelope.  In a read-only email,
     pops the envelope up in the overlay.
   - *Decode with mqc* — opens any `mqc-1` envelope you've
     selected and shows the plaintext in the overlay, with a
     **Copy to clipboard** button.

## Uninstall

```powershell
cd gmail-mqc-extension\host
.\uninstall.ps1 -Browser both
```
Then remove the extension from `chrome://extensions`.  Your
`~/.env` and `~/.TPM/` inside WSL are untouched — remove those by
hand if you're retiring the whole setup.

## Threat model (short form)

- Password material (`~/.env`, per-domain cache) never leaves WSL.
  The shim only sees opaque bytes going in and out.
- The extension runs only on `https://mail.google.com/*`; other
  pages don't see the context menu or the native-messaging port.
- The shim is accessible only to the registered extension ID via
  Chrome's `allowed_origins`, enforced by Chrome itself.  A second,
  unauthorised extension can't `connectNative("com.postwolf.mqc")`
  against your registered host.
- Gmail itself sees the ciphertext (since we paste the envelope
  into the compose body).  That's the point: Google's servers
  store only AES-256-GCM output, scrypt-derived keys never leave
  your box.

## Related docs

- `host/README.md` — shim install + troubleshooting
- `extension/README.md` — extension install + known limitations
- `../mtc-keymaster/README-mqc-cli.md` — full `mqc` CLI reference
- `../kit-mqc/README-mqc.md` — kit-mqc install (mqc on the WSL box)
- `../mtc-keymaster/README-bugsandtodo.md` §44 — the original
  design sketch this implements
