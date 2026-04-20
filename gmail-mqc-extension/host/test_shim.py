#!/usr/bin/env python3
"""
test_shim.py — exercise mqc_native_host.py over the same
length-prefixed-JSON protocol Chrome would use.

Usage:
  # From WSL (Linux):
  python3 test_shim.py                       # uses `mqc` directly (no wsl.exe)

  # From Windows PowerShell / cmd (with the host installed):
  py -3 test_shim.py --win                   # uses wsl.exe mqc via the real host

Not a substitute for a real Chrome load test, but enough to confirm
the shim's stdio framing and mqc invocation work before you wire up
the content script.
"""
import argparse
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HOST_SCRIPT = HERE / "mqc_native_host.py"


def frame(obj: dict) -> bytes:
    data = json.dumps(obj).encode("utf-8")
    return struct.pack("<I", len(data)) + data


def unframe(stream) -> dict | None:
    raw = stream.read(4)
    if len(raw) == 0:
        return None
    (length,) = struct.unpack("<I", raw)
    return json.loads(stream.read(length).decode("utf-8"))


def run_one_case(win_mode: bool, req: dict) -> dict:
    """Spawn the host, send one request, read one response, exit."""
    if win_mode:
        argv = ["py", "-3", str(HOST_SCRIPT)]
    else:
        # In WSL, bypass wsl.exe by monkey-patching the host's argv0
        # check — easiest is to just run the host directly and expect
        # `mqc` on PATH (which it will be after the kit install).
        argv = [sys.executable, str(HOST_SCRIPT)]

    env = os.environ.copy()
    if not win_mode:
        # The host always shells out to `wsl.exe mqc …`.  In a WSL
        # smoke test we want it to shell out to plain `mqc` — set
        # MQC_FORCE_LOCAL=1 to switch.  (Requires host support, see
        # mqc_native_host.py.)
        env["MQC_FORCE_LOCAL"] = "1"

    p = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    p.stdin.write(frame(req))
    p.stdin.close()
    resp = unframe(p.stdout)
    p.wait(timeout=10)
    err = p.stderr.read().decode("utf-8", errors="replace")
    if err.strip():
        print(f"[host stderr] {err.strip()}", file=sys.stderr)
    return resp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--win", action="store_true",
                    help="run on Windows via py -3 (uses wsl.exe)")
    args = ap.parse_args()

    print("=== 1. ping ===")
    r = run_one_case(args.win, {"op": "ping"})
    print(json.dumps(r, indent=2)[:400])
    assert r and r.get("ok"), f"ping failed: {r}"

    print("\n=== 2. encode ===")
    r = run_one_case(args.win, {"op": "encode", "body": "hello from shim test"})
    print(json.dumps(r, indent=2)[:400])
    assert r and r.get("ok"), f"encode failed: {r}"
    envelope = r["result"].strip()

    print("\n=== 3. decode (round-trip) ===")
    r = run_one_case(args.win, {"op": "decode", "body": envelope})
    print(json.dumps(r, indent=2)[:400])
    assert r and r.get("ok"), f"decode failed: {r}"
    plaintext = r["result"]
    assert plaintext.strip() == "hello from shim test", \
        f"round-trip mismatch: got {plaintext!r}"

    print("\n=== 4. error path (bad op) ===")
    r = run_one_case(args.win, {"op": "wat"})
    print(json.dumps(r, indent=2))
    assert r and not r.get("ok"), "expected error response"

    print("\n=== 5. error path (corrupted envelope) ===")
    r = run_one_case(args.win, {"op": "decode", "body": "{\"not\":\"real\"}"})
    print(json.dumps(r, indent=2))
    assert r and not r.get("ok"), "expected error response"

    print("\nAll cases passed.")


if __name__ == "__main__":
    main()
