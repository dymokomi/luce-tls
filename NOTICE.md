# Provenance

Original Luce Base TLS 1.3 helpers, Copyright 2026 Dy Mokomi, MIT OR Apache-2.0.
HKDF-Expand-Label follows RFC 8446 section 7.1 using `luce-crypto` HKDF-SHA-256.
DNS hostname matching follows the exact/wildcard subset of RFC 6125.
The bounded TLS Certificate list and X.509 path checks follow RFC 8446 section
4.4.2 and the applicable RFC 5280 basic path, extension, key-usage and EKU rules.
The embedded ISRG Root X2 P-384 public key is transcribed from the official
certificate at https://letsencrypt.org/certs/isrg-root-x2.pem.

No OpenSSL, BoringSSL or other foreign TLS/X.509 engine is linked. The live
certificate bytes in the deterministic test were publicly served by the Lucia
OS Caddy endpoint on 2026-09-19 and remain certificate material, not third-party
code.
