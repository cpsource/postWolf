#!/usr/bin/env python3
"""Check that the shared libraries qsh needs at runtime are installed.

This is a portability-tooling script: copy it to a new machine BEFORE
installing postWolf to find out which apt packages are missing, or run
it on an existing install with --binary to verify directly against
the linker's view of the qsh binary.

The default check uses a baked-in list of DT_NEEDED entries (the
direct dependencies the dynamic linker resolves at qsh startup).
Anything else in `ldd qsh` is transitive through these and will be
pulled in by apt when you install the listed packages.

Usage:
  ./check-qsh-deps.py                       # baked-in expected list
  ./check-qsh-deps.py --binary /path/to/qsh # pull live list from binary
  ./check-qsh-deps.py --strict              # also walk full ldd closure
"""

import argparse
import shutil
import subprocess
import sys

# Direct (DT_NEEDED) dependencies of qsh as built by the project's
# Makefile.tools after TODO #81 (libmqc.a client/server TU split).
# Format: (SONAME, apt package providing the runtime library, hint)
#
# libpostWolf is the only entry without an apt package — it ships from
# this source tree.  libc is always present on a glibc system.
EXPECTED = [
    ("libpostWolf.so.44", None,        "build + install from this postWolf tree"),
    ("libjson-c.so.5",    "libjson-c5", None),
    ("libaugeas.so.0",    "libaugeas0", None),
    ("libunbound.so.8",   "libunbound8", None),
    ("libcrypto.so.3",    "libssl3",   "ships in openssl 3.x"),
    ("libc.so.6",         None,        "glibc — always present"),
]


def ldconfig_index():
    """Return {soname: resolved-path} from ldconfig -p."""
    try:
        out = subprocess.run(
            ["ldconfig", "-p"],
            check=True, capture_output=True, text=True,
        ).stdout
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        sys.exit(f"failed to run ldconfig -p: {e}")
    index = {}
    for line in out.splitlines():
        parts = line.strip().split(" => ", 1)
        if len(parts) != 2:
            continue
        soname = parts[0].split()[0]
        index[soname] = parts[1]
    return index


def needed_from_binary(path):
    """Parse DT_NEEDED entries from readelf -d <path>."""
    if not shutil.which("readelf"):
        sys.exit("readelf not found; install binutils or run without --binary.")
    out = subprocess.run(
        ["readelf", "-d", path],
        check=True, capture_output=True, text=True,
    ).stdout
    needed = []
    for line in out.splitlines():
        if "(NEEDED)" not in line:
            continue
        # ...Shared library: [libfoo.so.N]
        start = line.find("[")
        end = line.find("]", start + 1)
        if start >= 0 and end > start:
            needed.append(line[start + 1:end])
    return needed


def ldd_closure(path):
    """Return list of (soname, resolved_path_or_None) from ldd."""
    if not shutil.which("ldd"):
        sys.exit("ldd not found; install glibc tools or skip --strict.")
    out = subprocess.run(
        ["ldd", path], check=True, capture_output=True, text=True,
    ).stdout
    entries = []
    for line in out.splitlines():
        line = line.strip()
        if not line or "statically linked" in line:
            continue
        if " => " in line:
            soname, rhs = line.split(" => ", 1)
            soname = soname.strip()
            resolved = rhs.split(" (")[0].strip()
            entries.append((soname, resolved if resolved != "not found" else None))
        elif line.startswith("/"):
            # vdso, ld-linux — listed without =>
            soname = line.split(" (")[0].strip()
            entries.append((soname.rsplit("/", 1)[-1], soname))
    return entries


def report(rows, index, *, pkg_for=None):
    """Print a status table for a list of (soname, package, hint) rows.
    If pkg_for is None, packages are looked up only in the hardcoded list.
    Returns the list of missing rows."""
    print(f"{'Library':<24} {'Status':<8} Path / Notes")
    print("-" * 70)
    missing = []
    for soname, pkg, hint in rows:
        path = index.get(soname)
        if path:
            print(f"{soname:<24} {'OK':<8} {path}")
        else:
            tail = hint or (f"apt install {pkg}" if pkg else "no apt package")
            print(f"{soname:<24} {'MISSING':<8} ({tail})")
            missing.append((soname, pkg, hint))
    return missing


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary",
                    help="Read DT_NEEDED from this binary instead of the baked-in list.")
    ap.add_argument("--strict", action="store_true",
                    help="Also check the full ldd transitive closure (requires --binary).")
    args = ap.parse_args()

    if args.strict and not args.binary:
        sys.exit("--strict requires --binary <path>")

    if not shutil.which("ldconfig"):
        sys.exit("ldconfig not found; this script needs glibc tools.")

    index = ldconfig_index()

    if args.binary:
        live = needed_from_binary(args.binary)
        # Merge live list with package hints from EXPECTED where we know them.
        hint_map = {soname: (pkg, hint) for soname, pkg, hint in EXPECTED}
        rows = [(s, *hint_map.get(s, (None, "unknown — check `apt-file search`"))) for s in live]
        print(f"Direct (DT_NEEDED) entries from {args.binary}:")
    else:
        rows = EXPECTED
        print("Expected qsh runtime dependencies (from baked-in list):")

    print()
    missing = report(rows, index)

    if args.strict:
        print()
        print("Strict mode — full ldd closure:")
        print()
        all_libs = ldd_closure(args.binary)
        unresolved = [(s, p) for s, p in all_libs if p is None]
        for s, p in all_libs:
            mark = "OK" if p else "MISSING"
            print(f"  {s:<28} {mark:<8} {p or ''}")
        if unresolved:
            print()
            print(f"{len(unresolved)} unresolved transitive(s): {[s for s,_ in unresolved]}")
            sys.exit(2)

    print()
    if missing:
        pkgs = [p for _, p, _ in missing if p]
        if pkgs:
            print(f"{len(missing)} missing dep(s).  Run:")
            print(f"  sudo apt update && sudo apt install -y {' '.join(pkgs)}")
        for soname, pkg, hint in missing:
            if not pkg:
                print(f"  {soname}: {hint or 'no apt package — install manually'}")
        sys.exit(1)
    print("All qsh runtime libraries are present.")


if __name__ == "__main__":
    main()
