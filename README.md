# luce-tls

Native Luce Base TLS 1.3. MIT OR Apache-2.0.

Client and server handshakes for one profile: `TLS_CHACHA20_POLY1305_SHA256`,
X25519, ECDSA-P256. Trust is a pinned issuer public key, not a system CA store.
`session.connect` / `session.accept` plus `x509.mint_self_signed` for private
servers. No resumption, client certificates, or other cipher suites.

Experimental, not security-reviewed.

```sh
python3 tools/bootstrap.py
python3 tests/run.py
python3 tests/sanitize.py
```
