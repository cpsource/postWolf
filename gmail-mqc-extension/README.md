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

---

## Complete Windows 11 install walkthrough

This is the end-to-end recipe that actually worked, including
every gotcha we hit during the first install.  Skip sections you've
already done; the order matters where noted.

### Prerequisites

- **Windows 11** with **WSL2** installed (`wsl --install`).
- **An Ubuntu WSL distro** — any version, 24.04 recommended.  You
  can check with `wsl -l -v`.
- **Python 3 on the Windows side** — the shim is a Python script;
  the `.cmd` launcher Chrome spawns needs `python` on `%PATH%`.
- **Chrome or Edge** with Developer-mode extensions allowed.

### Step 1 — install mqc inside WSL

On the postWolf build host, produce `postWolf-mqc-kit-<ver>.tar.gz`:

```bash
cd postWolf/kit-mqc
make build-kit
```

Copy that tarball to the Windows box, extract it inside WSL, then:

```bash
tar xzf postWolf-mqc-kit-<ver>.tar.gz
cd payload
sudo bash install-mqc-kit.sh
```

Verify inside WSL:

```bash
which mqc            # → /usr/local/bin/mqc
mqc --help           # prints usage
```

Set a master password in `~/.env` on the WSL side:

```bash
# pick a strong 16-char password using mqc itself
mqc --encode --complex-password </dev/null >/dev/null
# → prints "Generated password: <16 chars>" on stderr

# put it in ~/.env
echo 'MQC_MASTER_PASSWORD="<the 16 chars>"' > ~/.env
chmod 600 ~/.env
```

Round-trip check inside WSL:

```bash
echo hello | mqc --encode --env --no-cache \
           | mqc --decode --env --no-cache
# → hello
```

### Step 2 — build & transport the extension tarball

On the postWolf build host:

```bash
cd postWolf/gmail-mqc-extension
make build-kit
# → postWolf-gmail-mqc-ext-<ver>.tar.gz (≈ 17 KB)
```

Copy the tarball to the Windows box however is easiest (GitHub,
`scp`, `\\wsl$\Ubuntu\tmp\...`, USB).

### Step 3 — extract to a Windows path

The extension must live on the Windows filesystem (not inside WSL —
Chrome's Load-unpacked needs a Windows path, and `install.ps1` runs
in PowerShell).

From a WSL shell (any distro):

```bash
tar xzf /path/to/postWolf-gmail-mqc-ext-<ver>.tar.gz -C /mnt/c/Users/<you>/
# → C:\Users\<you>\gmail-mqc-extension\  on the Windows side
```

Or from PowerShell (Windows 10 1803+ has a built-in `tar`):

```powershell
cd C:\Users\<you>\
tar xzf C:\path\to\postWolf-gmail-mqc-ext-<ver>.tar.gz
```

### Step 4 — install Python (if not already present)

Run `python --version` in PowerShell.  If it prints the
Microsoft-Store "Python was not found" stub, install it:

```powershell
winget install --id Python.Python.3.12 -e
```

Wait for "Successfully installed", then **open a fresh PowerShell
window** (PATH doesn't update in shells that are already running)
and re-verify:

```powershell
python --version
# → Python 3.12.x
```

### Step 5 — unblock the PowerShell scripts

Windows marks files that crossed a trust boundary (tarball
downloaded, WSL interop, etc.) with a "downloaded" flag (MOTW) and
the default execution policy refuses to run them.  Fix, one-time
per-user:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
cd C:\Users\<you>\gmail-mqc-extension\host
Unblock-File .\install.ps1
Unblock-File .\uninstall.ps1
```

(Alternatively, run just the one install with a bypass:
`powershell -ExecutionPolicy Bypass -File .\install.ps1 -ExtensionId …`.
The first form is cleaner if you'll tweak the install later.)

### Step 6 — load the extension unpacked

1. Chrome → `chrome://extensions`.
2. Top-right: toggle **Developer mode** ON.
3. Click **Load unpacked**.
4. Select `C:\Users\<you>\gmail-mqc-extension\extension\`.
5. Note the 32-char **ID** on the extension's card — we need it next.

### Step 7 — find which WSL distro has mqc

If you have multiple distros (common!), `wsl.exe` defaults to one
that might not be where you installed mqc.  Check:

```powershell
wsl -l -v
# NAME            STATE           VERSION
# * Ubuntu-22.04    Stopped         2         ← default
#   Ubuntu          Running         2         ← has mqc
```

If the asterisked one is not the distro with `/usr/local/bin/mqc`,
either **make it the default**:

```powershell
wsl --set-default Ubuntu
```

**…or** pin the shim explicitly in the install step below
(`-WslDistro Ubuntu`).

Verify with:

```powershell
wsl mqc --help
# (or)
wsl -d Ubuntu mqc --help
```

Whichever prints the banner is what you'll want the shim to use.

### Step 8 — register the native-messaging host

From PowerShell in `gmail-mqc-extension\host\`:

```powershell
# If plain `wsl mqc --help` worked in step 7:
.\install.ps1 -ExtensionId <32-char-id>

# If you needed -d Ubuntu to reach mqc, pin it:
.\install.ps1 -ExtensionId <32-char-id> -WslDistro Ubuntu

# Or if Ubuntu is installed with a different default user:
.\install.ps1 -ExtensionId <32-char-id> -WslDistro Ubuntu -WslUser ubuntu
```

The script:

- Writes `com.postwolf.mqc.json` with absolute paths + your
  extension ID baked in.
- Creates the HKCU registry entry under
  `Software\Google\Chrome\NativeMessagingHosts\com.postwolf.mqc`
  (add `-Browser both` to also register with Edge; no admin
  needed).
- Persists `MQC_WSL_DISTRO` / `MQC_WSL_USER` / `MQC_WSL_PATH`
  as user-scope env vars so the shim reads them every time.

### Step 9 — fully close and reopen Chrome

Not just "reload the extension" — **close every Chrome window** so
the next launch inherits the env vars install.ps1 just set.
(Confirm via Task Manager if you're paranoid — `chrome.exe` must be
gone.)

### Step 10 — ping

Click the extension's toolbar icon (puzzle-piece → pin it for ease)
→ **Ping native host**.

Success looks like the first lines of `mqc --help` in the popup's
status box.  If you also see `wsl: Failed to translate 'E:\…'`
lines above the banner, that's WSL trying to mirror your Windows
`%PATH%` into the Linux shell and failing on entries whose drive
letter isn't auto-mounted.  It's cosmetic; ping still succeeded.
To silence permanently, inside your WSL distro:

```bash
sudo tee -a /etc/wsl.conf <<'EOF'

[interop]
appendWindowsPath = false
EOF
```

then from PowerShell: `wsl --shutdown`.  Next boot won't inherit
the Windows PATH at all.  mqc doesn't care about Windows exes.

### Step 11 — use it

1. Open `https://mail.google.com/`.
2. **Encode:** click *Compose*, type something, select the text,
   right-click → **Encode with mqc**.  The selection is replaced in
   place with a single-line `{"v":"mqc-1",...}` envelope.
3. **Decode:** select the envelope text (triple-click the line
   works), right-click → **Decode with mqc**.  A centered overlay
   pops up with the plaintext, a **Copy to clipboard** button, and
   an Esc-to-close escape hatch.

Both directions use the same `MQC_MASTER_PASSWORD` in `~/.env`
inside WSL.  Two peers who've agreed on that password can exchange
sealed envelopes over Gmail with no further key-management.

---

## Troubleshooting quick reference

| Symptom | Likely cause | Fix |
|---|---|---|
| `install.ps1 cannot be loaded — running scripts is disabled` | Default PowerShell execution policy. | Step 5. |
| `wsl: Failed to translate 'E:\…'` spam | Windows entries on drive letters that aren't auto-mounted in WSL. | `appendWindowsPath = false` in `/etc/wsl.conf` + `wsl --shutdown`. |
| `/bin/bash: line 1: mqc: command not found` | Default WSL shell has a truncated PATH. | Shim already uses absolute path; if you invoke mqc by hand use `/usr/local/bin/mqc`. |
| `/bin/bash: /usr/local/bin/mqc: No such file or directory` | `wsl.exe` is hitting a *different* distro than where you installed mqc. | `wsl -l -v`; `wsl --set-default <name>` or `install.ps1 -WslDistro <name>`. |
| Ping: "Error when communicating with the native messaging host" *and* `%LOCALAPPDATA%\postwolf-mqc\host.log` does NOT exist | Shim never started — Python missing, or extension-ID mismatch. | `python --version`; if it's the Store stub, step 4.  Then compare extension ID at `chrome://extensions` with `allowed_origins` in `com.postwolf.mqc.json`; rerun install.ps1 with the current ID. |
| Ping: error *and* `host.log` has a Python traceback | Shim ran but crashed. | Paste the traceback — it'll point at the exact line. |
| Context menu items don't appear on Gmail | Extension not loaded, or you're on a non-Gmail tab. | `chrome://extensions` → enabled?  Any red "Errors" button?  Reload the extension. |
| `mqc: no --domain passed and ~/.TPM/default does not resolve` | Running without `--env` on a box with no TPM setup. | Shim always uses `--env`; if you see this manually, add `--env` to your command. |

For deeper host-specific issues see
`host/README.md` ("Troubleshooting").

---

## Uninstall

```powershell
cd gmail-mqc-extension\host
.\uninstall.ps1 -Browser both
```

Removes the HKCU registry entries and clears the `MQC_WSL_*` env
vars.  Then remove the extension from `chrome://extensions`.
Your `~/.env` and `~/.TPM/` inside WSL are not touched — delete
them by hand if you're retiring the whole setup.

---

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

---

## Related docs

- `host/README.md` — shim install + troubleshooting
- `extension/README.md` — extension load + known limits
- `../mtc-keymaster/README-mqc-cli.md` — full `mqc` CLI reference
- `../kit-mqc/README-mqc.md` — kit-mqc install (mqc inside WSL)
- `../mtc-keymaster/README-bugsandtodo.md` §44 — the original
  design sketch this implements
