#!/usr/bin/env python3
"""Extract the RFC 8448 section 3 trace (Simple 1-RTT Handshake) into
tests/vectors/rfc8448_1rtt.txt.

Usage: tools/rfc8448_vectors.py RFC8448_TXT

Each line is `NAME HEX`. NAME is the step's party and title, an occurrence
number when the title repeats, and the item label, all lowercased with
underscores, e.g. server.send_handshake_record.2.complete_record. HEX is "-"
for an empty value.
"""
import collections
import hashlib
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
PAGE = re.compile(r"^(Thomson\s+Informational|RFC 8448\s+TLS 1.3 Traces)")


def slug(text):
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    text = Path(sys.argv[1]).read_text()
    section = text[text.index("\n3.  Simple 1-RTT Handshake"):text.index("\n4.  Resumed 0-RTT Handshake")]
    lines = [l for l in section.splitlines() if not PAGE.match(l)]
    seen, out, step, label, data = collections.Counter(), [], None, None, []
    def flush():
        nonlocal label, data
        if step and label and data:
            out.append(f"{step}.{label} {''.join(data)}")
        label, data = None, []
    for line in lines:
        head = re.match(r"^   \{(client|server)\}\s+(.*?):?\s*$", line)
        if head:
            flush()
            title = f"{head.group(1)}.{slug(head.group(2).split('(')[0])}"
            seen[title] += 1
            step = f"{title}.{seen[title]}"
            continue
        item = re.match(r"^      (\S.*?) \(\d+ octets\):\s+(.*)$", line)
        if item:
            flush()
            label = slug(item.group(1))
            value = item.group(2).replace(" ", "")
            data = ["-" if value == "(empty)" else value]
            continue
        if label and re.match(r"^\s+([0-9a-f]{2}\s?)+$", line):
            data.append(line.strip().replace(" ", ""))
            continue
        # Blank lines and page breaks may split one value, so only a new
        # item or step ends it.
    flush()
    target = ROOT / "tests/vectors/rfc8448_1rtt.txt"
    target.write_text("\n".join(out) + "\n")
    digest = hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest()
    (ROOT / "tests/vectors/RFC8448-SHA256SUM").write_text(f"{digest}  rfc8448.txt\n")
    print(f"{target.name}: {len(out)} items")


if __name__ == "__main__":
    main()
