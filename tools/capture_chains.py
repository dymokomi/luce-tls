#!/usr/bin/env python3
"""Capture real mail servers' certificate chains as test fixtures.

Runs `openssl s_client -showcerts` once per target and writes
tests/chains/HOST-PORT.txt: a `host` line, the capture time as `now` (Unix
seconds; the tests validate at this fixed instant), then one `cert HEX` line
per certificate in the order the server sent them. Needs the network; CI only
reads the committed fixtures.
"""
import base64
from pathlib import Path
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
TARGETS = [
    ("imap.gmail.com", 993, None), ("smtp.gmail.com", 465, None), ("smtp.gmail.com", 587, "smtp"),
    ("imap.mail.me.com", 993, None), ("smtp.mail.me.com", 587, "smtp"),
    ("outlook.office365.com", 993, None), ("smtp.office365.com", 587, "smtp"),
    ("imap.fastmail.com", 993, None), ("smtp.fastmail.com", 465, None),
]


def capture(host, port, starttls):
    command = ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host, "-showcerts"]
    if starttls:
        command += ["-starttls", starttls]
    output = subprocess.run(command, input=b"", capture_output=True, timeout=30).stdout.decode()
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", output, re.S)
    if not blocks:
        raise SystemExit(f"{host}:{port}: no certificates captured")
    return [base64.b64decode("".join(block.split())) for block in blocks]


def main():
    folder = ROOT / "tests/chains"
    folder.mkdir(parents=True, exist_ok=True)
    for host, port, starttls in TARGETS:
        certificates = capture(host, port, starttls)
        lines = [f"host {host}", f"now {int(time.time())}"] + [f"cert {der.hex()}" for der in certificates]
        (folder / f"{host}-{port}.txt").write_text("\n".join(lines) + "\n")
        print(f"{host}:{port}: {len(certificates)} certificates")


if __name__ == "__main__":
    main()
