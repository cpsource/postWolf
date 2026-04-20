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

- **"wsl.exe not found"** — install WSL2 (`wsl --install`) and
  restart Windows.
- **UTF-16 / CRLF garbage in responses** — make sure the install
  was done after a Windows 11 22H2 or later; older builds need
  `WSL_UTF8=1` (already set by the shim).
- **"mqc exited 1: …"** — read the inner message.  Common causes:
  `~/.env` missing `MQC_MASTER_PASSWORD=`, or the recipient used a
  different password on encode than decode.
- **"Native host has exited"** in Chrome's extension logs —
  check `host.log` for a Python traceback.  Typical culprit is
  python not on PATH; fix `mqc_native_host.cmd`'s `PYTHON=` line.
