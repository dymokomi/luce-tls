#!/usr/bin/env python3
"""Convert OpenSSL's TLS13-KDF test data into tests/vectors/openssl_tls13_kdf.txt.

Usage: tools/openssl_tls13_kdf.py OPENSSL_CHECKOUT

Reads test/recipes/30-test_evp_data/evpkdf_tls13_kdf.txt of OpenSSL (Apache-2.0,
The OpenSSL Project Authors). Only data is converted. Lines (hex, "-" empty):

  extract HASH KEY SALT LABEL OUTPUT   HKDF-Extract(salt', KEY), where salt' is
                                       zeros without SALT and otherwise
                                       Expand-Label(SALT, LABEL, Hash(""))
  expand HASH KEY CONTEXT LABEL OUTPUT HKDF-Expand-Label(KEY, LABEL, CONTEXT)
  skip REASON...                       a stanza outside this package, with why

KEY "-" in extract means zeros of the hash length. LABEL follows the stanza's
prefix, which the converter checks is "tls13 ".
"""
import collections
import hashlib
from pathlib import Path
import sys

REVISION = "adb795d9b166b7342ad1227b6241f3d31d973438"
ROOT = Path(__file__).resolve().parents[1]
SOURCE = "test/recipes/30-test_evp_data/evpkdf_tls13_kdf.txt"
HASHES = {"SHA2-256": "sha256", "SHA256": "sha256", "SHA2-384": "sha384"}
PREFIX = b"tls13 ".hex()


def stanzas(text):
    current = []
    for line in text.splitlines() + [""]:
        if line.startswith("#"):
            continue
        if not line.strip():
            if current:
                yield dict(current)
            current = []
            continue
        key, _, value = line.partition("=")
        current.append((key.strip(), value.strip()))


def value(stanza, name):
    """The hex value of Ctrl.NAME ("hexNAME:..."), or "-" when it is unset."""
    raw = stanza.get(f"Ctrl.{name}")
    return raw.split(":", 1)[1] or "-" if raw else "-"


def convert(stanza, skipped):
    if "KDF" not in stanza:
        return None
    if stanza.get("Availablein") == "fips":
        skipped["FIPS-provider-only check (approved digests, key lengths, indicators)"] += 1
        return "skip FIPS provider only"
    mode = stanza["Ctrl.mode"].split(":", 1)[1]
    digest = stanza["Ctrl.digest"].split(":", 1)[1]
    if mode not in ("EXTRACT_ONLY", "EXPAND_ONLY"):
        assert stanza.get("Result") == "KDF_CTRL_ERROR", stanza
        skipped[f"mode {mode}: OpenSSL refuses it at configuration; TLS 1.3 uses only extract and expand"] += 1
        return f"skip mode {mode}"
    if digest not in HASHES:
        skipped[f"digest {digest}: TLS 1.3 cipher suites use SHA-256 and SHA-384 only"] += 1
        return f"skip digest {digest}"
    assert "Result" not in stanza, stanza
    label = value(stanza, "label")
    if label != "-":
        assert value(stanza, "prefix") == PREFIX, stanza
    output = stanza["Output"]
    if mode == "EXTRACT_ONLY":
        return f"extract {HASHES[digest]} {value(stanza, 'key')} {value(stanza, 'salt')} {label} {output}"
    return f"expand {HASHES[digest]} {value(stanza, 'key')} {value(stanza, 'data')} {label} {output}"


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    path = Path(sys.argv[1]) / SOURCE
    skipped, lines = collections.Counter(), []
    for stanza in stanzas(path.read_text()):
        line = convert(stanza, skipped)
        if line:
            lines.append(line)
    target = ROOT / "tests/vectors/openssl_tls13_kdf.txt"
    target.write_text("\n".join(lines) + "\n")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    (ROOT / "tests/vectors/OPENSSL-SHA256SUMS").write_text(f"{digest}  {SOURCE} (revision {REVISION})\n")
    kept = sum(1 for l in lines if not l.startswith("skip"))
    print(f"{target.name}: {kept} cases; skipped " + "; ".join(f"{n} {why}" for why, n in skipped.items()))


if __name__ == "__main__":
    main()
