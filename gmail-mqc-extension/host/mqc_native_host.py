#!/usr/bin/env python3
"""
mqc_native_host.py — Chrome Native Messaging host that bridges the
Gmail extension to the `mqc` CLI living inside WSL2.

Protocol (see https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging):
  - stdin  : 4-byte LE length header + UTF-8 JSON body (one request)
  - stdout : same framing (one response per request)

Request schema (extension → host):
  {
    "op":     "encode" | "decode" | "ping",
    "body":   "<string>",            # plaintext for encode, envelope JSON for decode
    "domain": "<optional string>"    # passed to mqc as --domain; absent → --env fallback
  }

Response schema (host → extension):
  { "ok": true,  "result": "<string>" }
  { "ok": false, "error":  "<string>" }

This host does NOT touch keys, passwords, or the filesystem itself.
It shells out to `wsl.exe mqc …` and forwards stdin/stdout bytes.
All secrets stay inside WSL (~/.env, ~/.TPM/).

Log file (errors / diagnostics): %LOCALAPPDATA%\\postwolf-mqc\\host.log
"""
import json
import os
import struct
import subprocess
import sys
import traceback
from pathlib import Path

# Chrome defaults cap messages at 1 MB either direction; honour it.
MAX_MSG_BYTES = 1 * 1024 * 1024
# How long to wait for `wsl.exe mqc …` before giving up.
MQC_TIMEOUT_SEC = 30

# --- Logging (optional, to a file Chrome can't see) -----------------------
LOG_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "postwolf-mqc"
LOG_FILE = LOG_DIR / "host.log"


def log(msg: str) -> None:
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(msg.rstrip() + "\n")
    except Exception:
        pass  # logging is best-effort


# --- Native-messaging framing ---------------------------------------------
def read_message():
    """Read one length-prefixed JSON message from stdin; None on EOF."""
    raw = sys.stdin.buffer.read(4)
    if len(raw) == 0:
        return None
    if len(raw) != 4:
        raise IOError(f"short header: {len(raw)} byte(s)")
    (length,) = struct.unpack("<I", raw)
    if length == 0 or length > MAX_MSG_BYTES:
        raise IOError(f"bad message length: {length}")
    body = sys.stdin.buffer.read(length)
    if len(body) != length:
        raise IOError(f"short body: got {len(body)} of {length}")
    return json.loads(body.decode("utf-8"))


def send_message(obj) -> None:
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    if len(data) > MAX_MSG_BYTES:
        # Truncate error reports rather than crash.
        data = json.dumps(
            {"ok": False, "error": f"response too large ({len(data)} bytes)"}
        ).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("<I", len(data)))
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


# --- WSL / mqc bridge -----------------------------------------------------
#
# Environment knobs honoured by the shim:
#   MQC_FORCE_LOCAL   "1" → use plain `mqc` instead of `wsl.exe …`
#                           (used by test_shim.py inside WSL).
#   MQC_WSL_PATH      Absolute path to the mqc binary inside WSL.
#                     Default: /usr/local/bin/mqc (kit-mqc install).
#                     Using an absolute path bypasses $PATH issues in
#                     wsl.exe's non-interactive shell when systemd
#                     user-session setup or Windows PATH interop
#                     breaks the normal default PATH.
#   MQC_WSL_DISTRO    If set, passes `-d <distro>` to wsl.exe.
#   MQC_WSL_USER      If set, passes `-u <user>`   to wsl.exe.

def mqc_bin() -> str:
    return os.environ.get("MQC_WSL_PATH", "/usr/local/bin/mqc")


def wsl_prefix() -> list[str]:
    """The fixed `wsl.exe [-d …] [-u …]` prefix before the mqc path."""
    argv = ["wsl.exe"]
    distro = os.environ.get("MQC_WSL_DISTRO")
    user = os.environ.get("MQC_WSL_USER")
    if distro:
        argv += ["-d", distro]
    if user:
        argv += ["-u", user]
    return argv


def wsl_argv(op: str, domain: str | None) -> list[str]:
    """Build the command line for a given op.

    Normally `wsl.exe [-d …] [-u …] <mqc-abspath> …` (host runs on
    Windows, mqc in WSL).  If MQC_FORCE_LOCAL=1 we shell out to plain
    `mqc` on the current box instead — used by test_shim.py when
    running the smoke suite inside WSL without a Windows round-trip.
    """
    if op not in ("encode", "decode"):
        raise ValueError(f"unsupported op: {op!r}")
    if os.environ.get("MQC_FORCE_LOCAL") == "1":
        argv = ["mqc", f"--{op}", "--env", "--no-cache"]
    else:
        argv = wsl_prefix() + [mqc_bin(), f"--{op}", "--env", "--no-cache"]
    if domain:
        argv += ["--domain", domain]
    return argv


def call_mqc(op: str, body: str, domain: str | None) -> str:
    """Run `wsl.exe mqc …`, pipe body in, return stdout as str."""
    argv = wsl_argv(op, domain)
    env = os.environ.copy()
    # Force UTF-8 out of wsl.exe on older Windows builds that otherwise
    # emit UTF-16LE with a BOM.
    env["WSL_UTF8"] = "1"
    log(f"exec: {' '.join(argv)}  (body={len(body)} chars)")
    try:
        r = subprocess.run(
            argv,
            input=body.encode("utf-8"),
            capture_output=True,
            timeout=MQC_TIMEOUT_SEC,
            env=env,
            check=False,
        )
    except FileNotFoundError as e:
        raise RuntimeError(
            "wsl.exe not found on PATH — is WSL2 installed?"
        ) from e
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"mqc timed out after {MQC_TIMEOUT_SEC}s") from e

    if r.returncode != 0:
        stderr = r.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"mqc exited {r.returncode}: {stderr}")
    return r.stdout.decode("utf-8", errors="replace")


# --- Dispatch -------------------------------------------------------------
def handle(req: dict) -> dict:
    op = req.get("op")
    if op == "ping":
        # Cheap diagnostic: returns an mqc --help banner.
        try:
            if os.environ.get("MQC_FORCE_LOCAL") == "1":
                argv = ["mqc", "--help"]
            else:
                argv = wsl_prefix() + [mqc_bin(), "--help"]
            r = subprocess.run(
                argv,
                capture_output=True,
                timeout=5,
                env={**os.environ, "WSL_UTF8": "1"},
            )
            stdout = r.stdout.decode("utf-8", errors="replace")
            stderr = r.stderr.decode("utf-8", errors="replace")
            if r.returncode != 0:
                return {
                    "ok": False,
                    "error": f"ping: exit {r.returncode}\n"
                             f"argv: {' '.join(argv)}\n"
                             f"stderr: {stderr.strip()[:400]}",
                }
            banner = stdout or stderr
            return {"ok": True, "result": banner[:512]}
        except Exception as e:
            return {"ok": False, "error": f"ping failed: {e}"}

    if op not in ("encode", "decode"):
        return {"ok": False, "error": f"unsupported op: {op!r}"}

    body = req.get("body")
    if not isinstance(body, str):
        return {"ok": False, "error": "'body' must be a string"}
    if len(body.encode("utf-8")) > MAX_MSG_BYTES:
        return {"ok": False, "error": "body exceeds 1 MB limit"}

    domain = req.get("domain")
    if domain is not None and not isinstance(domain, str):
        return {"ok": False, "error": "'domain' must be a string if set"}

    try:
        result = call_mqc(op, body, domain)
        # mqc appends a trailing \n on encode; decode returns raw bytes
        # (we've already UTF-8-decoded them).  The extension strips as
        # it sees fit.
        return {"ok": True, "result": result}
    except Exception as e:
        log(f"ERROR: {e}\n{traceback.format_exc()}")
        return {"ok": False, "error": str(e)}


# --- Main loop ------------------------------------------------------------
def main() -> int:
    log(f"host start (pid={os.getpid()})")
    # Chrome connects with connectNative() → opens a port → sends one or
    # more messages → closes stdin on disconnect.  Handle them as they
    # arrive; exit cleanly on EOF.
    while True:
        try:
            req = read_message()
        except Exception as e:
            log(f"read error: {e}")
            send_message({"ok": False, "error": f"read: {e}"})
            return 1
        if req is None:
            log("host exit (EOF)")
            return 0
        resp = handle(req)
        try:
            send_message(resp)
        except Exception as e:
            log(f"write error: {e}")
            return 1


if __name__ == "__main__":
    sys.exit(main())
