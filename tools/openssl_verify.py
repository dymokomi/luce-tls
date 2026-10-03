#!/usr/bin/env python3
"""Port OpenSSL's certificate verification cases (test/recipes/25-test_verify.t).

Usage: tools/openssl_verify.py OPENSSL_CHECKOUT

Writes tests/x509/openssl/cases.txt and the DER form of every certificate the
kept cases use (from test/certs/*.pem, Apache-2.0, The OpenSSL Project
Authors):

  case NAME EXPECT UNIX_TIME - TRUSTED CHAIN

EXPECT is OpenSSL's verdict (accept/reject) unless POLICY gives this client's
own, with a reason; TRUSTED are certificates whose Name and key become trust
anchors; CHAIN is the target followed by the untrusted certificates. No host
name is checked ("-"), as `openssl verify` checks none. Calls that rely on
features this client does not have are counted in SKIPPED.txt by reason.
"""
import base64
import calendar
import collections
import hashlib
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "tests/x509/openssl"
# 2026-10-02T00:00:00Z: inside the validity of OpenSSL's long-lived test certs.
NOW = calendar.timegm((2026, 10, 2, 0, 0, 0))
TRUST_WORDS = ("serverAuth", "clientAuth", "anyEKU")

# Cases where this client deliberately differs, by description, with the
# client's verdict and the reason.
ANCHOR = "a trust anchor is a Name and key (RFC 5280 6.1.1); its certificate's own CA flag and EKU are not checked"
LEAF_ANCHOR = "a leaf certificate cannot be its own trust anchor"
WEAK_RSA = "RSA keys below 2048 bits are refused"
POLICY = {
    "accept_critical_OCSP_No_Check": ("reject", "unknown critical extensions, including OCSP no-check, are refused"),
    "fail_client_purpose": ("accept", ANCHOR),
    "fail_partial_chain_with_client_purpose": ("accept", ANCHOR),
    "fail_client_purpose_intermediate_trusted": ("accept", ANCHOR),
    "fail_non_CA_trust_store_intermediate": ("accept", ANCHOR),
    "fail_non_CA_trust_store_intermediate_2": ("accept", ANCHOR),
    "accept_last_resort_direct_leaf_match": ("reject", LEAF_ANCHOR),
    "accept_last_resort_direct_leaf_match_Ed25519_signed_self_issued_cert": ("reject", LEAF_ANCHOR),
    "accept_non_ca_with_pathlen_0_by_default": ("reject", "basicConstraints with pathLenConstraint but without cA is malformed (RFC 5280 4.2.1.9)"),
    "reject_RSA_2048_root_at_auth_level_3": ("accept", "the key-size floor is 2048 bits regardless of OpenSSL security levels"),
    "accept_RSA_768_root_at_auth_level_0": ("reject", WEAK_RSA),
    "accept_RSA_768_intermediate_at_auth_level_0": ("reject", WEAK_RSA),
    "accept_RSA_768_leaf_at_auth_level_0": ("reject", WEAK_RSA),
    "accept_md5_intermediate_at_auth_level_0": ("reject", "MD5 signatures are refused"),
    "accept_md5_leaf_at_auth_level_0": ("reject", "MD5 signatures are refused"),
    "Accept_PSS_signature_using_SHA1_at_auth_level_0": ("reject", "SHA-1 certificate signatures are refused"),
    "CA_PSS_signature": ("reject", "RSASSA-PSS-only (id-RSASSA-PSS) subject keys are not supported"),
}
for bits in ("224", "256", "384", "512"):
    for suffix in ("", "_w_fips"):
        POLICY[f"accept_cert_generated_with_EC_and_SHA3_{bits}{suffix}"] = ("reject", "SHA-3 signatures are not implemented")
for name in ("Name_Constraints_everything_permitted", "Name_Constraints_nothing_excluded",
             "Name_Constraints_nested_test_all_permitted", "Name_Constraints_CNs_permitted",
             "Name_Constraints_CNs_permitted_no_SAN_extension", "Name_constraints_URI_with_userinfo",
             "Name_constraints_bad_othername_name_constraint", "Not_too_many_names_and_constraints_to_check_1",
             "Not_too_many_names_and_constraints_to_check_2", "Not_too_many_names_and_constraints_to_check_3"):
    POLICY[name] = ("reject", "certificates with name constraints are refused (not implemented)")
for name in ("accept_X25519_EE_cert_issued_by_trusted_Ed25519_self_signed_CA_cert", "accept_trusted_Ed25519_self_signed_CA_cert"):
    POLICY[name] = ("reject", "Ed25519 signatures are not implemented")


def description_key(text):
    return re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_")


def der_of(pem_path):
    text = pem_path.read_text()
    match = re.search(r"-----BEGIN (TRUSTED )?CERTIFICATE-----(.*?)-----END", text, re.S)
    if not match:
        return None
    data = base64.b64decode("".join(match.group(2).split()))
    # A TRUSTED CERTIFICATE appends auxiliary trust data after the certificate.
    length = data[1]
    if length & 0x80:
        count = length & 0x7F
        length = 2 + count + int.from_bytes(data[2:2 + count], "big")
    else:
        length = 2 + length
    return data[:length]


def split_args(text):
    parts, depth, current = [], 0, ""
    for ch in text:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(current.strip())
            current = ""
        else:
            current += ch
    parts.append(current.strip())
    return parts


def names(text):
    text = text.strip()
    inner = re.search(r"\[(.*)\]", text, re.S).group(1)
    words = re.findall(r'qw\((.*?)\)|"([^"]+)"', inner, re.S)
    out = []
    for qw, quoted in words:
        out += qw.split() if qw else [quoted]
    return out


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    source = Path(sys.argv[1]) / "test"
    script = (source / "recipes/25-test_verify.t").read_text()
    calls = re.findall(r'ok\((!?)verify\((.*?)\),\s*"([^"]*)"\);', script, re.S)
    OUT.mkdir(parents=True, exist_ok=True)
    skipped, lines, used, seen = collections.Counter(), [], set(), collections.Counter()
    for negated, arguments, description in calls:
        parts = split_args(arguments)
        target, purpose = parts[0].strip('"'), parts[1].strip('"')
        trusted, untrusted = names(parts[2]), names(parts[3])
        options = [p.strip('"') for p in parts[4:]]
        if purpose not in ("sslserver", ""):
            skipped[f"purpose {purpose} (only TLS server certificates are validated)"] += 1
            continue
        if any(w in n for n in trusted + untrusted for w in TRUST_WORDS):
            skipped["OpenSSL auxiliary trust settings on certificates"] += 1
            continue
        unsupported = [o for o in options if o.startswith("-") and o not in ("-partial_chain", "-auth_level", "-attime")]
        if unsupported:
            skipped[f"option {unsupported[0]}"] += 1
            continue
        now = NOW
        if "-attime" in options:
            now = int(options[options.index("-attime") + 1])
        files = []
        missing = False
        for name in [target] + untrusted + trusted:
            der = der_of(source / "certs" / f"{name}.pem")
            if der is None:
                missing = True
                break
            (OUT / f"{name}.der").write_bytes(der)
            used.add(name)
        if missing:
            skipped["certificate file without a certificate"] += 1
            continue
        expect = "reject" if negated else "accept"
        key = description_key(description)
        seen[key] += 1
        if seen[key] > 1:
            key = f"{key}_{seen[key]}"
        if key in POLICY:
            expect = POLICY[key][0]
        chain = ",".join(f"{n}.der" for n in [target] + untrusted)
        anchors = ",".join(f"{n}.der" for n in trusted) or "-"
        lines.append(f"case {key} {expect} {now} - {anchors} {chain}")
    (OUT / "cases.txt").write_text("\n".join(lines) + "\n")
    (OUT / "SKIPPED.txt").write_text("".join(f"{n} {why}\n" for why, n in sorted(skipped.items())))
    (OUT / "POLICY.txt").write_text("".join(f"{k}: {v} ({why})\n" for k, (v, why) in sorted(POLICY.items())))
    (OUT / "SOURCE-SHA256SUMS").write_text(
        f"{hashlib.sha256((source / 'recipes/25-test_verify.t').read_bytes()).hexdigest()}  test/recipes/25-test_verify.t\n")
    print(f"cases.txt: {len(lines)} cases, {len(used)} certificates; skipped {sum(skipped.values())}")


if __name__ == "__main__":
    main()
