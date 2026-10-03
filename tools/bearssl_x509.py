#!/usr/bin/env python3
"""Port BearSSL's X.509 validation suite (test/x509/alltests.txt) to luce-tls.

Usage: tools/bearssl_x509.py BEARSSL_CHECKOUT

Copies the suite's certificate and Name files (MIT, Copyright (c) 2016 Thomas
Pornin) into tests/x509/bearssl/ and writes tests/x509/bearssl/cases.txt:

  anchor NAME KIND SUBJECT_HEX KEY_A KEY_B   (KIND rsa, p256, p384, p521, ee)
  case NAME EXPECT UNIX_TIME HOST ANCHORS CHAIN

EXPECT is accept or reject. It is BearSSL's verdict unless this client's
policy differs; POLICY lists each difference with its reason, and those cases
carry the client's own verdict. Cases this client cannot express are written
as `skip REASON` and counted by the test. HOST is "-" when BearSSL checks no
name; ANCHORS and CHAIN are comma-separated anchor names and file names.
"""
import calendar
import hashlib
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "tests/x509/bearssl"
DEFAULT_TIME = "2016-08-30T18:00:00Z"

# Cases where this client deliberately differs from BearSSL, with its verdict.
POLICY = {
    "goodName3": ("reject", "no common-name fallback: only subjectAltName dNSName entries are matched"),
    "hashSHA1": ("reject", "SHA-1 certificate signatures are refused"),
    "secp256r1-sha1": ("reject", "SHA-1 certificate signatures are refused"),
    "rsa1017": ("reject", "RSA keys below 2048 bits are refused"),
}
# Cases outside what this client can express.
SKIP = {
    "directTrust": "end-entity trust anchors are not supported",
    "ignoredSignature1": "end-entity trust anchors are not supported",
    "ignoredSignature2": "end-entity trust anchors are not supported",
    "hashSHA256Unsupported": "the set of accepted hash functions is not configurable",
    "secp521r1": "P-521 is not implemented",
}


def sections(text):
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("["):
            current = {"kind": line.strip("[]")}
            yield current
            continue
        key, _, value = line.partition("=")
        current[key.strip()] = value.strip()


def unix(stamp):
    stamp = stamp.replace(" ", "T").rstrip("Z")
    return calendar.timegm(time.strptime(stamp, "%Y-%m-%dT%H:%M:%S"))


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    source = Path(sys.argv[1]) / "test/x509"
    OUT.mkdir(parents=True, exist_ok=True)
    text = (source / "alltests.txt").read_text()
    entries = list(sections(text))
    keys = {e["name"]: e for e in entries if e["kind"] == "key"}
    lines, files = [], set()
    for entry in entries:
        if entry["kind"] != "anchor":
            continue
        key = keys[entry["key"]]
        subject = (source / entry["DN_file"]).read_bytes().hex()
        files.add(entry["DN_file"])
        if entry.get("type") == "EE":
            kind, a, b = "ee", "-", "-"
        elif key["type"] == "RSA":
            kind, a, b = "rsa", key["n"].lower(), key["e"].lower()
        else:
            point = key["q"].lower()
            width = (len(point) - 2) // 2
            kind = {"P-256": "p256", "P-384": "p384", "P-521": "p521"}[key["curve"]]
            a, b = point[2:2 + width], point[2 + width:]
        lines.append(f"anchor {entry['name']} {kind} {subject} {a} {b}")
    for entry in entries:
        if entry["kind"] != "chain":
            continue
        name = entry["name"]
        chain = entry["chain"].split()
        files.update(chain)
        expect = "accept" if entry["status"] == "0" else "reject"
        if name in POLICY:
            expect = POLICY[name][0]
        if name in SKIP:
            expect = "skip"
        host = entry.get("servername", "-")
        anchors = ",".join(entry.get("anchors", "").split()) or "-"
        lines.append(f"case {name} {expect} {unix(entry.get('time', DEFAULT_TIME))} {host} {anchors} {','.join(chain)}")
    for name in sorted(files):
        shutil.copyfile(source / name, OUT / name)
    (OUT / "cases.txt").write_text("\n".join(lines) + "\n")
    notes = [f"{name}: {verdict} ({reason})" for name, (verdict, reason) in POLICY.items()]
    notes += [f"{name}: skipped ({reason})" for name, reason in SKIP.items()]
    (OUT / "POLICY.txt").write_text("\n".join(notes) + "\n")
    (OUT / "SOURCE-SHA256SUMS").write_text(f"{hashlib.sha256((source / 'alltests.txt').read_bytes()).hexdigest()}  alltests.txt\n")
    print(f"cases.txt: {sum(1 for l in lines if l.startswith('case'))} cases, {len(files)} files")


if __name__ == "__main__":
    main()
