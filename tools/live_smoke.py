#!/usr/bin/env python3
"""Build tools/live_smoke.lucb and run it against real mail servers.

Needs the network, so CI never runs it. Exit status is non-zero when any
host fails. Pass --base to use an existing luce-base compiler.
"""
import argparse
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
TARGETS = [
    ("imaps", "imap.gmail.com", 993),
    ("smtps", "smtp.gmail.com", 465),
    ("smtp-starttls", "smtp.gmail.com", 587),
    ("imaps", "imap.mail.me.com", 993),
    ("smtp-starttls", "smtp.mail.me.com", 587),
    ("imaps", "outlook.office365.com", 993),
    ("smtp-starttls", "smtp.office365.com", 587),
    ("imaps", "imap.fastmail.com", 993),
    ("smtps", "smtp.fastmail.com", 465),
    ("imap-starttls", "outlook.office365.com", 143),
    ("https", "kinogaki.com", 443),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, default=ROOT / "build/toolchain/luce-base")
    parser.add_argument("targets", nargs="*", help="MODE:HOST:PORT entries (default: the built-in list)")
    args = parser.parse_args()
    environment = dict(os.environ)
    environment.setdefault("LUCE_STD", str(ROOT.parent / "luce-base/src/std"))
    environment.setdefault("LUCE_CACHE", str(ROOT / "build/cache"))
    binary = ROOT / "build/live-smoke"
    subprocess.run([str(args.base.resolve()), "build", str(ROOT / "tools/live_smoke.lucb"), "--native",
                    "--opt", "2", "-o", str(binary)], cwd=ROOT, env=environment, check=True, timeout=600)
    targets = [tuple(entry.split(":")) for entry in args.targets] or TARGETS
    failed = 0
    for mode, host, port in targets:
        print(f"== {mode} {host}:{port}", flush=True)
        result = subprocess.run([str(binary), mode, host, str(port)], timeout=90)
        failed += result.returncode != 0
    print(f"{len(targets) - failed}/{len(targets)} hosts passed")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
