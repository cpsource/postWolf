# postWolf mqc — Chrome native-messaging host ("the shim")

This is the Windows-side bridge between the Gmail Chrome extension
(to be built) and the `mqc` CLI running inside WSL2.  Chrome speaks
Native Messaging (length-prefixed JSON over stdio); this shim
translates those messages into `wsl.exe mqc …` invocations and
forwards the results back.

**Password material never touches Windows.**  The shim just shuttles
opaque bytes; `mqc` itself reads `~/.env` / `~/.TPM/` from inside
WSL where it already lives.

## Files

| File | Role |
|---|---|
| `mqc_native_host.py` | The shim itself.  Reads length-prefixed JSON from stdin, runs `wsl.exe mqc`, writes the result back. |
| `mqc_native_host.cmd` | Windows launcher — finds `python` on PATH and runs the .py.  Chrome calls this file. |
| `com.postwolf.mqc.json.template` | Native-messaging manifest template.  `install.ps1` substitutes the absolute path + extension ID. |
| `install.ps1` | Writes the manifest and the `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.postwolf.mqc` registry entry. |
| `uninstall.ps1` | Removes the registry entry. |
| `test_shim.py` | Offline test harness that talks to the shim over the same wire protocol Chrome uses.  Runnable in WSL (`MQC_FORCE_LOCAL=1`) or on Windows (`--win`). |

## Request / response schema

Extension → shim:
```json
{ "op": "encode" | "decode" | "ping",
  "body":   "<plaintext or envelope JSON>",
  "domain": "<optional string; defaults to --env fallback>" }
```

Shim → extension:
```json
{ "ok": true,  "result": "<string>" }
{ "ok": false, "error":  "<string>" }
```

`ping` returns the first 512 chars of `mqc --help` — useful as a
post-install liveness check.

## Install (on Windows 11)

Prereqs:
- WSL2 Ubuntu 24.04 with the mqc kit installed (`install-mqc-kit.sh`)
  and `~/.env` populated with `MQC_MASTER_PASSWORD="..."`.
- Python 3 on the Windows PATH (`winget install Python.Python.3`
  or the Microsoft Store build).
- The Chrome extension loaded unpacked; note its 32-char ID from
  `chrome://extensions`.

Then from a PowerShell in this directory:

```powershell
.\install.ps1 -ExtensionId abcdefghijklmnopqrstuvwxyzabcdef
# or for both Chrome and Edge:
.\install.ps1 -ExtensionId ... -Browser both
```

The script writes `com.postwolf.mqc.json` next to itself with the
correct absolute path, then registers it under
`HKCU\Software\Google\Chrome\NativeMessagingHosts\com.postwolf.mqc`
pointing at that manifest.

### PowerShell execution policy

On a fresh Windows box the default policy blocks unsigned scripts
and you'll see:

    File install.ps1 cannot be loaded because running scripts is
    disabled on this system.  … UnauthorizedAccess

Two ways past it:

```powershell
# one-shot bypass (no policy change):
powershell -ExecutionPolicy Bypass -File .\install.ps1 `
           -ExtensionId abcdefghijklmnopqrstuvwxyzabcdef

# or permanent per-user (recommended):
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
Unblock-File .\install.ps1          # clears the "downloaded" MOTW flag
Unblock-File .\uninstall.ps1
.\install.ps1 -ExtensionId abcdefghijklmnopqrstuvwxyzabcdef
```

### Telling the shim which WSL distro/user has mqc

If `wsl whoami` returns a user that doesn't have mqc on PATH — or
`wsl mqc --help` says *command not found* even though
`/usr/local/bin/mqc` exists — it's usually because the default WSL
user's shell starts with a truncated `$PATH` (systemd-user-session
failure, Windows-PATH interop noise, etc.).  The shim side-steps
this by using an absolute path to `mqc` inside WSL
(`/usr/local/bin/mqc` by default) and lets you pin the distro/user
via install-time switches:

```powershell
.\install.ps1 -ExtensionId <id> -WslDistro Ubuntu -WslUser ubuntu
```

These persist as `MQC_WSL_DISTRO` / `MQC_WSL_USER` in your user
environment; the shim reads them on every invocation.  Override the
binary location with `-MqcPath /some/other/path` if you installed
mqc outside `/usr/local/bin/`.

**Important:** environment variables only affect *new* processes.
After running install.ps1, close and re-open Chrome so its
extension host picks up the updated vars.

## Test without the extension

**Inside WSL** (uses local `mqc`, no Windows round-trip):
```bash
cd gmail-mqc-extension/host
python3 test_shim.py
# → exercises ping, encode, decode, bad-op, corrupted-envelope
```

**On Windows** (uses the real `wsl.exe mqc` path):
```powershell
cd gmail-mqc-extension\host
py -3 test_shim.py --win
```

Both should print "All cases passed."

## Logging

Errors are appended to `%LOCALAPPDATA%\postwolf-mqc\host.log`
(Windows) or `~/.local/share/postwolf-mqc/host.log` on Linux — the
shim uses `$LOCALAPPDATA` if set, otherwise `$HOME`.  Chrome
swallows the shim's stderr, so this is the only way to see crashes
after-the-fact.

## Uninstall

```powershell
.\uninstall.ps1 -Browser both
```

Removes the registry entries.  Deleting the `gmail-mqc-extension\`
folder completes cleanup — no other filesystem state is kept on the
Windows side.

## Troubleshooting

First step, always: read `%LOCALAPPDATA%\postwolf-mqc\host.log`.
If the file *doesn't exist*, the shim never started — Python
missing, .cmd not on disk, or Chrome refused to launch it
(extension-ID mismatch).  If the file *does exist*, tail it for a
Python traceback that names the exact line that failed.

| Symptom | Likely cause | Fix |
|---|---|---|
| `install.ps1 : File … cannot be loaded because running scripts is disabled` | Default PowerShell execution policy blocks unsigned scripts. | Either one-shot `powershell -ExecutionPolicy Bypass -File .\install.ps1 -ExtensionId …`, or permanently: `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` then `Unblock-File .\install.ps1`. |
| `Python was not found; run without arguments to install from the Microsoft Store` | Python isn't installed — you're hitting Microsoft's install-redirector stub. | `winget install --id Python.Python.3.12 -e`.  **Open a fresh PowerShell** afterwards (PATH changes only apply to new shells). |
| `mqc-native-host: python not found on PATH` (from running `mqc_native_host.cmd` by hand) | Same as above.  Python genuinely isn't reachable. | Same fix. |
| Ping: *Error when communicating with the native messaging host* **and** `host.log` is absent | Shim never started.  Most common causes: (a) Python missing, (b) extension-ID mismatch between `com.postwolf.mqc.json` `allowed_origins` and the current `chrome://extensions` ID. | Check Python per above; compare IDs and re-run `install.ps1 -ExtensionId <current>`. Then **fully close and reopen Chrome**. |
| Ping: *Error …* **and** `host.log` has a Python traceback | Shim ran and crashed. | The traceback names the line; paste it into an issue or fix locally. |
| `/bin/bash: line 1: mqc: command not found` when running `wsl mqc --help` | Default WSL shell starts with a truncated `$PATH` (systemd-user-session failure or interop noise) — mqc exists at `/usr/local/bin/mqc` but the shell doesn't see it. | The shim already uses the absolute path; run `wsl /usr/local/bin/mqc --help` to confirm.  If that works, ping should work too. |
| `/bin/bash: /usr/local/bin/mqc: No such file or directory` | `wsl.exe` is landing in a distro that doesn't have mqc installed. | `wsl -l -v` — note which distro has the asterisk.  Either `wsl --set-default <distro-with-mqc>`, or pin the shim: `.\install.ps1 -ExtensionId <id> -WslDistro <name>`. |
| `wsl: Failed to translate 'E:\…'` warnings mixed into ping output | WSL's interop is trying to mirror your Windows `%PATH%` into `$PATH` at login, and a drive letter on `%PATH%` isn't auto-mounted. | Benign — ping still succeeds.  Silence permanently, inside WSL: append `[interop]\nappendWindowsPath = false\n` to `/etc/wsl.conf`, then `wsl --shutdown` from PowerShell. |
| UTF-16 / CRLF garbage in responses | Older Windows build without the `WSL_UTF8=1` behaviour. | Already set by the shim; upgrade to Windows 11 22H2 or later if it still bites you. |
| `mqc exited 1: mqc: authentication tag mismatch — wrong password or corrupted ciphertext` | Recipient's `MQC_MASTER_PASSWORD` differs from sender's, or the envelope was truncated in transit. | Check both sides' `~/.env`; re-copy the envelope. |
| `mqc exited 1: mqc: unsupported mqc format version` | You fed a non-`mqc-1` JSON object to `--decode`. | Not an mqc envelope; nothing to decode. |
| "Native host has exited" in Chrome's extension logs | The shim crashed mid-conversation. | Check `host.log` for the traceback. |

Notes on the extension-ID dance: Chrome assigns a stable ID to a
packed extension but a deterministic-from-disk-path ID to an
unpacked one.  Moving the `extension/` folder → new ID.  Whenever
you see a new ID in `chrome://extensions`, re-run
`install.ps1 -ExtensionId <that one>` and fully restart Chrome.
