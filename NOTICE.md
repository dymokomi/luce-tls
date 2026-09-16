# Provenance

Original Luce Base TLS 1.3 helpers, Copyright 2026 Dy Mokomi, MIT OR Apache-2.0.
HKDF-Expand-Label follows RFC 8446 section 7.1 using `luce-crypto` HKDF-SHA-256.
DNS hostname matching follows the exact/wildcard subset of RFC 6125.

This is not a TLS handshake, X.509 path builder or HTTPS client. No OpenSSL,
BoringSSL or other foreign TLS engine is linked.
