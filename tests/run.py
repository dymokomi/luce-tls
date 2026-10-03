#!/usr/bin/env python3
"""Build and test TLS helpers in every pinned mode."""
import argparse
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MODES = {f"native{i}": ["--native", "--opt", str(i)] for i in range(4)}
MODES.update({"c": ["--backend=c"], "c-release": ["--backend=c", "--release"]})
SOURCES = [
    ("src/tls_tests.lucb", "tls-tests"),
    ("src/session_tests.lucb", "session-tests"),
    ("src/stream_tests.lucb", "stream-tests"),
    ("src/handshake_tests.lucb", "handshake-tests"),
    ("src/x509_tests.lucb", "x509-tests"),
    ("src/chain_tests.lucb", "chain-tests"),
    ("src/mail_chain_tests.lucb", "mail-chain-tests"),
    ("src/x509_suite_tests.lucb", "x509-suite-tests"),
    ("src/rfc8448_tests.lucb", "rfc8448-tests"),
    ("src/tls13_kdf_tests.lucb", "tls13-kdf-tests"),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=[*MODES, "all"], default="all")
    parser.add_argument("--base", type=Path, default=ROOT / "build/toolchain/luce-base")
    args = parser.parse_args()
    if not args.base.is_file():
        raise SystemExit("Run python3 tools/bootstrap.py first")
    environment = dict(os.environ, LUCE_BASE=str(args.base.resolve()))
    environment.setdefault("LUCE_STD", str(ROOT.parent / "luce-base/src/std"))
    environment.setdefault("LUCE_CACHE", str(ROOT / "build/cache"))
    def run(command):
        print("RUN", " ".join(str(a) for a in command), flush=True)
        timeout = 600 if len(command) > 1 and command[1] == "build" else 120
        subprocess.run([str(a) for a in command], cwd=ROOT, env=environment, check=True, timeout=timeout)
    for mode, flags in MODES.items():
        if args.mode not in (mode, "all"): continue
        output = ROOT / "build" / mode
        output.mkdir(parents=True, exist_ok=True)
        print(f"MODE {mode}", flush=True)
        for source, name in SOURCES:
            run([args.base.resolve(), "build", ROOT / source, *flags, "-o", output / name])
            run([output / name])
        print(f"PASS {mode}", flush=True)
    print("PASS all selected compiler modes", flush=True)


if __name__ == "__main__":
    main()
