# postWolf mqc — Gmail Chrome extension

Right-click selected text in Gmail → **Encode with mqc** (seals
with AES-256-GCM) or **Decode with mqc** (opens an `mqc-1`
envelope).  All crypto runs inside WSL2 via the `mqc` CLI; the
extension only shuttles bytes.

## Contents

| File | Role |
|---|---|
| `manifest.json` | Manifest V3 — `nativeMessaging`, `contextMenus`, `scripting`, `notifications`; host permission for `mail.google.com` only. |
| `background.js` | Service worker — owns the two context-menu items and the `com.postwolf.mqc` native-messaging port. |
| `content_script.js` | Installs `window.__postwolfMqcShowOverlay` on Gmail pages so decode results pop up cleanly. No Gmail-DOM hacking. |
| `overlay.css` | Scoped styles for the result overlay (prefixed `.postwolf-mqc-*` to avoid colliding with Gmail). |
| `popup.html` / `popup.js` | Toolbar-action popup — single **Ping native host** button, useful as a post-install liveness check. |

## Prerequisites

Before loading this extension you must have the shim installed on
Windows.  See `../host/README.md` — summary:

1. WSL2 Ubuntu 24.04 with the mqc kit installed
   (`sudo bash install-mqc-kit.sh` from `kit-mqc/`) and
   `~/.env` populated with `MQC_MASTER_PASSWORD="..."`.
2. Python 3 on the Windows PATH.
3. Register the shim (substitute the ID printed by
   `chrome://extensions` *after* loading this extension):
   ```powershell
   cd gmail-mqc-extension\host
   .\install.ps1 -ExtensionId <32-char-id>
   ```

## Load (unpacked)

1. Chrome → `chrome://extensions`.
2. Toggle **Developer mode** on (top-right).
3. Click **Load unpacked** → select this `extension/` folder.
4. Note the 32-char **ID** Chrome shows for the extension.
5. In PowerShell, run `host/install.ps1 -ExtensionId <that id>`
   to register the native-messaging host against this specific
   extension ID.
6. Reload the extension (circular arrow button) after running
   install.ps1, so Chrome re-reads the native-host allowlist.

## Use

1. Open Gmail in Chrome.
2. **Encode:** in a compose window, type or select plaintext,
   right-click the selection → *Encode with mqc*.  The selection is
   replaced with a single-line `mqc-1` JSON envelope.
3. **Decode:** in a received message, select the entire envelope
   (triple-click the line works), right-click → *Decode with mqc*.
   An overlay pops up with the plaintext; click **Copy to
   clipboard** or press Esc to dismiss.

Errors (host unreachable, wrong password, corrupted envelope, …)
appear as Chrome notifications with the underlying mqc stderr.

## Ping diagnostic

Click the extension's toolbar icon → **Ping native host**.  A
successful ping prints the first few lines of `mqc --help` from
inside WSL.  If ping fails, check:

1. `wsl mqc --help` works in a Windows terminal.
2. `host/install.ps1` was run with the correct extension ID.
3. After the install, the extension was reloaded.
4. `%LOCALAPPDATA%\postwolf-mqc\host.log` on Windows for a Python
   traceback.

## Security model

- The extension only runs on `mail.google.com`
  (`host_permissions`); other pages don't see the context menu.
- No secret material ever leaves WSL.  `~/.env` +
  `~/.TPM/<domain>/mqc-password.pw` are read only by `mqc` inside
  the WSL distro; the Windows shim gets plaintext and ciphertext
  bytes but never the password.
- `clipboardWrite` is requested so the overlay's **Copy** button
  works without a user-agent prompt on every click.
- No analytics, no network calls, no remote code loading.  The
  service worker only `connectNative()`s to a single registered
  host name.

## Known limitations

- Encode-in-place works only in `contenteditable` selections
  (Gmail compose).  Selecting read-only text and choosing *Encode*
  just shows the result in the overlay.
- Gmail's plaintext compose mode handles the JSON envelope fine
  (it's a single line).  Rich-text mode may wrap or hyperlink
  parts of the envelope; switch to plaintext composition
  (⋮ menu → "Plain text mode") before encoding important content.
- Large messages (>1 MB either direction) are refused by the shim
  per Chrome's native-messaging cap.  Ordinary email bodies fit
  easily.

## Packaging

To package as a `.zip` for distribution:
```bash
cd extension
zip -r postwolf-mqc-gmail-0.1.0.zip . -x '*.DS_Store' -x 'icons/.gitkeep'
```

To build a signed `.crx`: use Chrome's "Pack extension" in developer
mode or `chrome --pack-extension=...`.  Extension-ID stability
across repacks requires keeping the same private key (`.pem`).
